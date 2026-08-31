// Fixture source for tests/data/permissive-tls.dex (dexllm#53).
//
// Authored rather than copied, and every shape in it earns its place — a
// correctness review found THREE load-bearing lines whose mutants survived the
// whole guard file because the first cut of this file could not distinguish them:
// the `<init>` filter, the caller dedupe and the caller sort in `_constructed_in`,
// plus the second component of the documented row sort.
//
//   PermissiveVerifier   verify() returns the constant true — PERMISSIVE
//                        + a non-ctor method and TWO constructors, so a
//                          `constructed_in` that forgets to filter, dedupe or
//                          sort produces a DIFFERENT answer here
//   PermissiveTrust      checkServerTrusted() is empty — PERMISSIVE
//   CheckingVerifier     verify() actually compares — must NOT be reported
//   CheckingTrust        checkServerTrusted() throws — must NOT be reported
//   PermissiveBoth       implements BOTH interfaces, so it is the only class
//                        yielding TWO rows — the row sort's second component
//   Installer / AInstaller
//                        construct them through the PLATFORM APIs, so the dex
//                        also carries a CUSTOM_TLS_TRUST hit beside the verdicts

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

class PermissiveVerifier implements HostnameVerifier {
    PermissiveVerifier() {
    }

    // A SECOND constructor, so `_constructed_in` concatenates two caller lists
    // and its sort has something to do.
    PermissiveVerifier(int unused) {
    }

    public boolean verify(String hostname, SSLSession session) {
        return true;
    }

    // A non-constructor method with its own caller: `constructed_in` must NOT
    // name that caller.
    void helper() {
    }
}

class PermissiveTrust implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

class CheckingVerifier implements HostnameVerifier {
    public boolean verify(String hostname, SSLSession session) {
        return "example.com".equals(hostname);
    }
}

class CheckingTrust implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        throw new CertificateException("no");
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

/** The one class yielding TWO rows — both permissive. */
class PermissiveBoth implements HostnameVerifier, X509TrustManager {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

class Installer {
    static void install() throws Exception {
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
                new PermissiveVerifier());
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
        ctx.init(null, new javax.net.ssl.TrustManager[] {new PermissiveTrust()}, null);
    }

    // Calls the NON-constructor method, and constructs the SAME class twice, so
    // the dedupe has something to collapse.
    static void touch() {
        PermissiveVerifier v = new PermissiveVerifier();
        v.helper();
        new PermissiveVerifier().helper();
    }
}

/**
 * Sorts BEFORE `Installer` by descriptor while being reached through the SECOND
 * constructor overload, so `_constructed_in`'s per-constructor CONCATENATION is
 * not already in sorted order and its sort has an effect.
 */
class AInstaller {
    static void install() throws Exception {
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
                new PermissiveVerifier(1));
        javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
        ctx.init(null, new javax.net.ssl.TrustManager[] {new PermissiveBoth()}, null);
    }

    /** Calls the non-ctor method WITHOUT constructing — the `<init>` filter. */
    static void poke(PermissiveVerifier v) {
        v.helper();
    }
}

// ── the three shapes an adversarial review built, each now a control ─────────

/**
 * An empty 2-arg `checkServerTrusted` beside a 3-arg sibling that PINS a
 * hostname. Conscrypt's `Platform.checkServerTrusted` duck-types its way to the
 * 3-arg overload, so this class is CORRECT and calling it permissive is a false
 * accusation. Must be `not_proven`.
 */
class DuckTrust implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType, String host)
            throws CertificateException {
        if (!"pinned.example.com".equals(host)) {
            throw new CertificateException("bad host");
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

/** The same trap reached through the platform BASE CLASS. Must be `not_proven`. */
class ExtTrust extends javax.net.ssl.X509ExtendedTrustManager
        implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType,
            java.net.Socket socket) {
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType,
            javax.net.ssl.SSLEngine engine) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType,
            java.net.Socket socket) throws CertificateException {
        throw new CertificateException("no");
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType,
            javax.net.ssl.SSLEngine engine) throws CertificateException {
        throw new CertificateException("no");
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}

/** A SUB-interface, like the legacy Apache `X509HostnameVerifier`. */
interface SubVerifier extends HostnameVerifier {
    void verifyHost(String host);
}

/**
 * Its trust-all implementor declares the SUB-interface, not the platform one, so
 * it is invisible — the documented bound. Its body is exactly the shape the
 * detector proves, which is what makes the bound worth pinning.
 */
class SubAllowAll implements SubVerifier {
    public boolean verify(String hostname, SSLSession session) {
        return true;
    }

    public void verifyHost(String host) {
    }
}

/**
 * The INHERITED form of the same trap: `InheritTrust` declares only the 2-arg
 * `checkServerTrusted`, so the declared-sibling test sees nothing — the overload
 * Conscrypt would duck-type (`Class#getMethod` searches the hierarchy) lives on
 * the base. Only the superclass test can decline it.
 */
abstract class BaseTrust implements X509TrustManager {
    public void checkServerTrusted(X509Certificate[] chain, String authType, String host)
            throws CertificateException {
        throw new CertificateException("bad host");
    }
}

class InheritTrust extends BaseTrust implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
