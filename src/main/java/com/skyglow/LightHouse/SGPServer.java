package com.skyglow.LightHouse;

import com.skyglow.LightHouse.config.ServerConfig;
import com.skyglow.LightHouse.db.Database;
import com.skyglow.LightHouse.event.ServerEvents;
import com.skyglow.LightHouse.router.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * TLS listener: accepts connections and hands each to an {@link SGPConnection}
 * on its own virtual thread. {@link #start()} blocks, call {@link #stop()} from
 * another thread.
 */
public final class SGPServer {

    private static final Logger log = LoggerFactory.getLogger(SGPServer.class);

    /** A socket that connects and then goes silent must not pin a thread forever. */
    private static final int TLS_HANDSHAKE_TIMEOUT_MS = 30_000;

    private final ServerConfig config;
    private final Database     db;
    private final Router       router;
    private final ServerEvents events;
    private final SSLContext   sslContext;

    private volatile boolean running = false;
    private SSLServerSocket serverSocket;

    public SGPServer(ServerConfig config, Database db, Router router, ServerEvents events) throws Exception {
        this.config     = config;
        this.db         = db;
        this.router     = router;
        this.events     = events;
        this.sslContext = buildSSLContext(config.certPath(), config.keyPath(), config.regCaPath());
    }

    /** Accepts connections until {@link #stop()} is called. One bad accept never kills the listener. */
    public void start() throws IOException {
        serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket();
        serverSocket.setEnabledProtocols(config.tlsProtocols());
        serverSocket.setNeedClientAuth(false);
        serverSocket.setWantClientAuth(config.requireRegCert());
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(config.tcpPort()));

        running = true;
        log.info("SGP/2 server listening on port {} [{}]{}", config.tcpPort(),
                String.join(", ", config.tlsProtocols()),
                config.requireRegCert() ? " (registration requires client certificate)" : " (registration OPEN)");

        while (running) {
            try {
                SSLSocket client = (SSLSocket) serverSocket.accept();
                Thread.ofVirtual()
                        .name("sgp-conn-" + client.getRemoteSocketAddress())
                        .start(() -> handle(client));
            } catch (IOException | RuntimeException e) {
                if (running) log.error("Accept error: {}", e.toString(), e);
            }
        }

        log.info("SGP/2 server stopped");
    }

    private void handle(SSLSocket client) {
        try {
            client.setSoTimeout(TLS_HANDSHAKE_TIMEOUT_MS);
            client.startHandshake();
            new SGPConnection(client, config, db, router, events).run();
        } catch (SSLException e) {
            log.warn("TLS handshake failed: {}", e.getMessage());
            closeQuietly(client);
        } catch (IOException e) {
            log.warn("Connection setup IO error: {}", e.getMessage());
            closeQuietly(client);
        }
    }

    public void stop() {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) closeQuietly(serverSocket);
    }

    private static void closeQuietly(Closeable c) {
        try { c.close(); } catch (IOException ignored) {}
    }

    /** Certificate chain plus unencrypted PKCS#8 key, RSA falling back to EC. */
    private static SSLContext buildSSLContext(String certPath, String keyPath, String regCaPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        List<Certificate> certs = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(certPath)) {
            certs.addAll(cf.generateCertificates(fis));
        }
        if (certs.isEmpty()) throw new IllegalArgumentException("No certificates found in: " + certPath);

        String keyBase64 = java.nio.file.Files.readString(java.nio.file.Path.of(keyPath)).trim()
                .replaceAll("-----BEGIN.*?-----", "")
                .replaceAll("-----END.*?-----", "")
                .replaceAll("\\s+", "");
        byte[] keyDer = Base64.getDecoder().decode(keyBase64);

        PrivateKey privateKey;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyDer));
        } catch (Exception e) {
            privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(keyDer));
        }

        Certificate[] chain = certs.toArray(new Certificate[0]);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("server", privateKey, new char[0], chain);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), trustManagers(cf, regCaPath), null);

        if (chain[0] instanceof X509Certificate x509) {
            log.info("TLS cert loaded: subject={} expires={}",
                    x509.getSubjectX500Principal().getName(), x509.getNotAfter());
        }
        return ctx;
    }

    /** PKIX-validates presented client certificates against the registration CA when one is set. */
    private static TrustManager[] trustManagers(CertificateFactory cf, String regCaPath) throws Exception {
        if (regCaPath == null) return new TrustManager[]{ new AcceptAllClientsTrustManager() };

        List<Certificate> caCerts = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(regCaPath)) {
            caCerts.addAll(cf.generateCertificates(fis));
        }
        if (caCerts.isEmpty()) throw new IllegalArgumentException("No CA certificates found in: " + regCaPath);

        KeyStore caStore = KeyStore.getInstance("PKCS12");
        caStore.load(null, null);
        for (int i = 0; i < caCerts.size(); i++) caStore.setCertificateEntry("reg-ca-" + i, caCerts.get(i));

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(caStore);
        log.info("Registration CA loaded from {} ({} certificate(s))", regCaPath, caCerts.size());
        return tmf.getTrustManagers();
    }

    /**
     * Without a registration CA there is nothing to validate
     * against, and client identity is proven by SGP/2's challenge-response.
     */
    private static final class AcceptAllClientsTrustManager implements X509TrustManager {
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
