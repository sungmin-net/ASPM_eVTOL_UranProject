package kr.ac.snu.mmlab.apm.uam;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static kr.ac.snu.mmlab.apm.uam.ApmEnums.*;

public class ApmUamNodeMain {

    private static final String UID = "UAM1";

    private static final String MAGIC = "APM";
    private static final String POLICY_DIR_PREFIX = MAGIC + "_P";
    private static final String BROADCAST_ADDRESS = "192.168.0.255";
    private static final String KEYSTORE_PASS = "mmlabmmlab"; // TODO apply timestamp based HMAC protection

    private static final SimpleDateFormat TIME_STAMP_FORMAT = new SimpleDateFormat("yyMMddHHmmss");
    private static final int BROADCAST_INTERVAL_MSEC = 3000;
    private static final int TIME_STAMP_VALID_MSEC = 5000;
    private static final int BROADCAST_PORT = 50000;
    private static final int UDP_BUFFER_SIZE = 2048;    // BR msg size is 1,383 bytes
    private static final int TLS_BUFFER_SIZE = 4096;

    private static boolean mIsBroadcasting = false;
    private static boolean mIsUpdating = false;
    private static boolean mIsListening = false;
    private static boolean mIsResponding = false;
    private static long mLastApmPolicyVer = 0;  // default
    private static String mLastFingerprint = "0"; // default
    private static DatagramSocket mUdpSocket = null;
    private static KeyStore mKeyStore = null;
    private static SSLSocketFactory mTlsSocketFactory = null;
    private static CertificateFactory mCertFactory = null;

    static Thread mBroadcaster = new Thread(new Runnable() {

        @Override
        public void run() {
            System.out.println("# Broadcaster started.");
            mIsBroadcasting = true;
            try {
                while (mIsBroadcasting && !mUdpSocket.isClosed()) {
                    if (mIsUpdating || mIsResponding) {
                        Thread.sleep(BROADCAST_INTERVAL_MSEC);
                        continue;
                    }
                    refreshCurrentApmPolicy();

                    String msg = getBroadcastMsg();

                    DatagramPacket packet = new DatagramPacket(msg.getBytes(),
                            msg.getBytes().length, InetAddress.getByName(BROADCAST_ADDRESS),
                            BROADCAST_PORT);

                    mUdpSocket.send(packet);
                    System.out.println("# SENT: " + msg);
                    Thread.sleep(BROADCAST_INTERVAL_MSEC);
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                System.out.println("# Broadcaster stopped.");
                mIsBroadcasting = false;
            }
        }

        private String getBroadcastMsg() throws UnrecoverableKeyException, InvalidKeyException,
                JSONException, KeyStoreException, NoSuchAlgorithmException,
                InvalidAlgorithmParameterException, SignatureException,
                UnsupportedEncodingException, CertificateEncodingException {
            JSONObject brMsg = new JSONObject();
            brMsg.put(Payload.Magic.toString(), MAGIC);

            JSONArray signed = new JSONArray();
            signed.put(new JSONObject().put(Signed.Issuer.toString(), UID));
            signed.put(new JSONObject().put(Signed.TimeStamp.toString(), getTimeStamp()));
            signed.put(new JSONObject().put(Signed.CurPolicyVer.toString(), mLastApmPolicyVer));

            brMsg.put(Payload.Signed.toString(), signed);
            brMsg.put(Payload.Signature.toString(), getSign(signed.toString()));
            brMsg.put(Payload.Cert.toString(), getCert());

            return brMsg.toString();
        }
    });

    static class Responder extends Thread {

        String mServIp;
        int mServPort;
        long mPeerVer;

        public Responder(String servInfo, long peerVer) {
            String[] peerIpPort = servInfo.split(":");
            mServIp = peerIpPort[ 0 ];
            mServPort = Integer.parseInt(peerIpPort[ 1 ]);
            mPeerVer = peerVer;
        }

        @Override
        public void run() {
            System.out.println("# Responder started.");
            mIsResponding = true;
            SSLSocket socket = null;
            try {
                socket = (SSLSocket) mTlsSocketFactory.createSocket(mServIp, mServPort);
                socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
                ZipOutputStream zos = new ZipOutputStream(socket.getOutputStream());

                File curDir = new File(System.getProperty("user.dir"));
                for (File f : curDir.listFiles()) {
                    if (f.isDirectory() && f.getName().startsWith(POLICY_DIR_PREFIX) &&
                            Long.parseLong(f.getName().replace(POLICY_DIR_PREFIX, "")) > mPeerVer) {
                        zipOutHelper(f, f.getName(), zos);
                    }
                }
                zos.close();

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                System.out.println("# Responder stopped.");
                mIsResponding = false;
                if (socket != null && !socket.isClosed()) {
                    try {
                        socket.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }

        private void zipOutHelper(File fileToZip,
                String fileName /* for recursion */, ZipOutputStream zos) throws IOException {
            if (fileToZip.isHidden()) {
                return;
            }
            if (fileToZip.isDirectory()) {
                if (fileName.endsWith("/")) {
                    zos.putNextEntry(new ZipEntry(fileName));
                } else {
                    zos.putNextEntry(new ZipEntry(fileName + "/"));
                }
                zos.closeEntry();
                File[] children = fileToZip.listFiles();
                for (File childFile : children) {
                    zipOutHelper(childFile, fileName + "/" + childFile.getName(), zos);
                }
                return;
            }
            FileInputStream fis = new FileInputStream(fileToZip);
            ZipEntry zipEntry = new ZipEntry(fileName);
            zos.putNextEntry(zipEntry);
            byte[] bytes = new byte[ TLS_BUFFER_SIZE ];
            int length;
            while ((length = fis.read(bytes)) >= 0) {
                zos.write(bytes, 0, length);
            }
            fis.close();
        }
    }

    static class Updater extends Thread {

        InetAddress mPeerAddr;
        String mPeerUid;

        public Updater(InetAddress peerAddr, String peerUid) {
            mPeerAddr = peerAddr;
            mPeerUid = peerUid;
        }

        @Override
        public void run() {
            System.out.println("# Updater started.");
            mIsUpdating = true;
            SSLServerSocket servSock = null;
            try {
                byte[] buf = new byte[ TLS_BUFFER_SIZE ];

                // 1. Open TLS server to receive newer policy
                SSLServerSocketFactory sslServSockFactory =
                        (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                servSock = (SSLServerSocket) sslServSockFactory.createServerSocket(
                        0 /* random available port */);
                servSock.setEnabledCipherSuites(servSock.getSupportedCipherSuites());

                // 2. Send newer policy requesting msg
                String reqMsg = getRequestMsg(InetAddress.getLocalHost().getHostAddress(),
                        servSock.getLocalPort());
                DatagramPacket reqPacket = new DatagramPacket(reqMsg.getBytes(),
                        reqMsg.getBytes().length, mPeerAddr, BROADCAST_PORT);
                mUdpSocket.send(reqPacket);
                System.out.println("# Requested " + mPeerUid + " "
                        + "to send newer APM policies.");

                // 3. receive peer's APM policies
                // Note: a single zip stream can have multiple APM policy directories
                SSLSocket recvSock = (SSLSocket) servSock.accept();
                ZipInputStream zis = new ZipInputStream(recvSock.getInputStream());
                ZipEntry zipEntry = zis.getNextEntry();
                File curDir = new File(System.getProperty("user.dir"));
                while (zipEntry != null) {
                    File destFile = new File(curDir, zipEntry.getName());

                    String destDirPath = curDir.getCanonicalPath();
                    String destFilePath = destFile.getCanonicalPath();

                    if (!destFilePath.startsWith(destDirPath + File.separator)) {
                        throw new IOException("Entry is outside of the target dir: " +
                                zipEntry.getName());
                    }

                    if (zipEntry.isDirectory()) {
                        if (!destFile.isDirectory() && !destFile.mkdirs()) {
                            throw new IOException("Failed to create directory " + destFile);
                        }
                    } else {
                        File parent = destFile.getParentFile();
                        if (!parent.isDirectory() && !parent.mkdirs()) {
                            throw new IOException("Failed to create directory " + parent);
                        }

                        // write file content
                        FileOutputStream os = new FileOutputStream(destFile);
                        int len;
                        while ((len = zis.read(buf)) > 0) {
                            os.write(buf, 0, len);
                        }
                        os.close();
                    }
                    zipEntry = zis.getNextEntry();
                }
                zis.closeEntry();
                zis.close();
                refreshCurrentApmPolicy();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                System.out.println("# Updater stopped.");
                mIsUpdating = false;
                if (servSock != null && !servSock.isClosed()) {
                    try {
                        servSock.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }

        private String getRequestMsg(String hostAddress, int localPort) throws Exception {
            JSONObject reqMsg = new JSONObject();
            reqMsg.put(Payload.Magic.toString(), MAGIC);

            JSONArray signed = new JSONArray();
            signed.put(new JSONObject().put(Signed.Issuer.toString(), UID));
            signed.put(new JSONObject().put(Signed.TimeStamp.toString(), getTimeStamp()));
            signed.put(new JSONObject().put(Signed.CurPolicyVer.toString(), mLastApmPolicyVer));
            signed.put(new JSONObject().put(Signed.ServInfo.toString(),
                    hostAddress + ":" + localPort));

            reqMsg.put(Payload.Signed.toString(), signed);
            reqMsg.put(Payload.Signature.toString(), getSign(signed.toString()));
            reqMsg.put(Payload.Cert.toString(), getCert());

            return reqMsg.toString();
        }
    }

    static Thread mListener = new Thread(new Runnable() {
        @Override
        public void run() {
            System.out.println("# Listener started.");
            mIsListening = true;
            byte[] buf = new byte[ UDP_BUFFER_SIZE ];

            try {
                while (mIsListening && !mUdpSocket.isClosed()) {
                    DatagramPacket packet = new DatagramPacket(buf, buf.length);
                    mUdpSocket.receive(packet);
                    String msg = new String(packet.getData(), 0, packet.getLength());
                    JSONObject msgJson = new JSONObject(msg);
                    JSONArray peerSigned = msgJson.getJSONArray(Payload.Signed.toString());
                    String peerUid = peerSigned.getJSONObject(Signed.Issuer.ordinal())
                            .getString(Signed.Issuer.toString());

                    // skip my br msg
                    if (UID.equals(peerUid)) {
                        continue;
                    }

                    System.out.println("# RECEIVED: " + msg);

                    if (mIsUpdating) {
                        System.out.println("# DISCARDED: Node is being updated.");
                        continue;
                    }

                    if (mIsResponding) {
                        System.out.println("# DISCARDED: Node is responding request.");
                        continue;
                    }

                    // verify msg
                    // 1. Peer cert verification
                    byte[] peerCertBytes = Base64.getDecoder().decode(msgJson.getString(
                            Payload.Cert.toString()));
                    if (!isValidCert(peerCertBytes)) {
                        System.out.println("# DISCARDED: Certificate verification failed.");
                        continue;
                    }

                    // 2. Signature verification
                    byte[] signedBytes = msgJson.getJSONArray(Payload.Signed.toString()).toString()
                            .getBytes();
                    byte[] signBytes = Base64.getDecoder().decode(msgJson.getString(
                            Payload.Signature.toString()));
                    Certificate peerCert = mCertFactory.generateCertificate(
                            new ByteArrayInputStream(peerCertBytes));
                    if (!isValidSignature(signedBytes, signBytes, peerCert)) {
                        System.out.println("# DISCARDED: Signature verification failed.");
                        continue;
                    }

                    // 3. Timestamp check
                    if (!hasValidTimeStamp(msgJson)) {
                        System.out.println("# DISCARDED: Timestamp validation failed.");
                        continue;
                    }

                    // Case#1. peer's policy version is higher than mine, call Updater.
                    long peerVersion = peerSigned.getJSONObject(Signed.CurPolicyVer.ordinal())
                            .getLong(Signed.CurPolicyVer.toString());
                    if (peerVersion > mLastApmPolicyVer) {
                        new Updater(packet.getAddress(), peerUid).start();
                        continue;
                    }

                    // Case#2. peer requests new APM policies
                    if (peerSigned.length() >= 4 && peerSigned.getJSONObject(
                            Signed.ServInfo.ordinal()).has(Signed.ServInfo.toString())) {
                        System.out.println(2222);
                        String servInfo = peerSigned.getJSONObject(
                                Signed.ServInfo.ordinal()).getString(
                                Signed.ServInfo.toString());
                        new Responder(servInfo, peerVersion).start();
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                System.out.println("# Listener stopped.");
                mIsListening = false;
                mIsUpdating = false;
                mIsResponding = false;
            }
        }

        private boolean hasValidTimeStamp(JSONObject msgJson) throws ParseException {
            String peerTimeStamp = msgJson.getJSONArray(Payload.Signed.toString())
                    .getJSONObject(Signed.TimeStamp.ordinal())
                    .getString(Signed.TimeStamp.toString());

            Date issued = TIME_STAMP_FORMAT.parse(peerTimeStamp);
            Date now = new Date();
            return now.getTime() - issued.getTime() < TIME_STAMP_VALID_MSEC;
        }
    });

    public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, KeyManagementException {

        Security.addProvider(new BouncyCastleProvider());

        mUdpSocket = new DatagramSocket(BROADCAST_PORT);
        mUdpSocket.setBroadcast(true);

        mCertFactory = CertificateFactory.getInstance("X.509");
        loadKeystore();
        initTlsSocketFactory();
        mListener.start();
        mBroadcaster.start();

        System.out.println("# APM " + UID + " node started.");
        System.out.println("# Enter \'q\' to quit.");
        Scanner scanner = new Scanner(System.in);
        String cmd = scanner.nextLine();
        if ("q".equals(cmd)) {
            mIsBroadcasting = false;
            mIsListening = false;
            if (!mUdpSocket.isClosed()) {
                mUdpSocket.close();
            }
        }
    }

    static void initTlsSocketFactory() throws NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, CertificateException, IOException {

        System.setProperty("javax.net.ssl.keyStore", MAGIC + "_" + UID + ".p12");
        System.setProperty("javax.net.ssl.keyStorePassword", KEYSTORE_PASS);

        // pin trust chain to APM_Root certificate
        Certificate rootCert  = mKeyStore.getCertificateChain(MAGIC + "_" + UID)[ 1 ]; // APM_Root
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", rootCert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext tlsContext = SSLContext.getInstance("TLS");
        tlsContext.init(null, tmf.getTrustManagers(), null);
        mTlsSocketFactory = tlsContext.getSocketFactory();
    }

    static boolean isValidCert(byte[] certBytes) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate peerCert = certFactory.generateCertificate(
                    new ByteArrayInputStream(certBytes));

            Certificate[] certChain = mKeyStore.getCertificateChain(MAGIC + "_" + UID);
            // cert to verify is pinned to APM_Root cert
            peerCert.verify(certChain[ 1 /* See CN=APM_Root*/ ].getPublicKey());
            return true;
        } catch (CertificateException | KeyStoreException | InvalidKeyException |
                NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();
        }

        return false;
    }

    static boolean isValidSignature(byte[] signedBytes, byte[] signBytes, Certificate cert)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, SignatureException {
        Signature verifier = Signature.getInstance("SHA256withRSA/PSS");
        verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                32, 1));
        verifier.initVerify(cert);
        verifier.update(signedBytes);
        return verifier.verify(signBytes);
    }

    static void refreshCurrentApmPolicy() throws IOException, NoSuchAlgorithmException,
            CertificateException, InvalidKeyException, InvalidAlgorithmParameterException,
            SignatureException {
        File curDir = new File(System.getProperty("user.dir"));
        FilenameFilter nameFilter = new FilenameFilter() {
            @Override
            public boolean accept(File file, String name) {
                return file.isDirectory() && name.startsWith(POLICY_DIR_PREFIX);
            }
        };

        List<String> fileNameList = new ArrayList<>(); // to avoid I/O
        for (String s : curDir.list(nameFilter)) {
            fileNameList.add(s);
        }

        Collections.sort(fileNameList);
        boolean removeNext = false;
        for (String fileName : fileNameList) {
            long newVer = Long.parseLong(fileName.replace(POLICY_DIR_PREFIX, ""));
            if (mLastApmPolicyVer < newVer) {
                if (removeNext) {
                    removeApmPolicy(newVer);
                    continue;
                }
                if (isNewApmPolicyVerified(newVer)) {
                    System.out.println("# UPDATED: " + mLastApmPolicyVer + " -> " + newVer);
                    mLastApmPolicyVer = newVer;
                } else {
                    removeNext = true;
                    removeApmPolicy(newVer);
                }
            }
        }
    }

    private static void removeApmPolicy(long ver) {
        new File(POLICY_DIR_PREFIX + ver + "\\policy.json").delete();
        new File(POLICY_DIR_PREFIX + ver + "\\manifest.json").delete();
        new File(POLICY_DIR_PREFIX + ver + "\\x509cert.pem").delete();
        new File(POLICY_DIR_PREFIX + ver).delete();
        System.out.println("# APM policy " + ver + " removed.");
    }

    private static boolean isNewApmPolicyVerified(long newVer) throws IOException,
            NoSuchAlgorithmException, CertificateException, InvalidKeyException,
            InvalidAlgorithmParameterException, SignatureException {

        JSONArray newPolicy = new JSONArray(new String(Files.readAllBytes(Paths.get(
                POLICY_DIR_PREFIX + newVer + File.separator + "policy.json"))));

        JSONArray newManifest = new JSONArray(new String(Files.readAllBytes(Paths.get(
                POLICY_DIR_PREFIX + newVer + File.separator + "manifest.json"))));

        JSONArray newMetadata = newManifest.getJSONObject(Manifest.Metadata.ordinal()).getJSONArray(
                Manifest.Metadata.toString());

        // 1. verify new policy's fingerprint
        String newMetadataFingerprint = newMetadata.getJSONObject(Metadata.Fingerprint.ordinal())
                .getString(Metadata.Fingerprint.toString());
        String newPolicyFingerprint = getFingerprint(newPolicy.toString());
        if (newPolicyFingerprint == null || !newPolicyFingerprint.equals(newMetadataFingerprint)) {
            System.out.println("# APM policy " + newVer + " has invalid fingerprint.");
            return false;
        }

        // 2. verify new policy's previous fingerprint
        String newMetadataPrevFingerprint = newMetadata.getJSONObject(
                Metadata.PrevFingerprint.ordinal()).getString(Metadata.PrevFingerprint.toString());
        if (!mLastFingerprint.equals(newMetadataPrevFingerprint)) {
            System.out.println("# APM policy " + newVer + " has invalid previous fingerprint.");
            return false;
        }

        // 3. verify new APM policy's signature
        byte[] signBytes = Base64.getDecoder().decode(newManifest.getJSONObject(
                Manifest.Signature.ordinal()).getString(Manifest.Signature.toString()));
        byte[] signedBytes = newMetadata.toString().getBytes();
        Certificate cert = mCertFactory.generateCertificate(new FileInputStream(POLICY_DIR_PREFIX
                + newVer + File.separator + "x509cert.pem"));
        if (!isValidSignature(signedBytes, signBytes, cert)) {
            System.out.println("# APM policy " + newVer + " has invalid signature.");
            return false;
        }

        // 4. verify issuer and cert owner
        String payloadIssuer = newPolicy.getJSONObject(Policy.Issuer.ordinal()).getString(
                Policy.Issuer.toString());
        String certCn = ((X509Certificate) cert).getSubjectX500Principal().getName()
                .split("=")[1].trim().replace(MAGIC + "_", "");
        if (payloadIssuer == null || !payloadIssuer.equals(certCn)) {
            System.out.println("# APM policy " + newVer + " has unmatched issuer.");
            return false;
        }

        // before return, update mLastFingerprint
        mLastFingerprint = newMetadataFingerprint;
        return true;
    }

    private static String getFingerprint(String s) throws NoSuchAlgorithmException {
        // Note. fingerprint is sha256 hashed Base64 string
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(s.getBytes()); // Note. do not add json indentation
        return Base64.getEncoder().encodeToString(md.digest());
    }

    static void loadKeystore() throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException {
        mKeyStore = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream(new File(MAGIC + "_" + UID + ".p12"));
        mKeyStore.load(fis, KEYSTORE_PASS.toCharArray());
    }

    static String getCert() throws CertificateEncodingException, KeyStoreException {
        return Base64.getEncoder().encodeToString(
                mKeyStore.getCertificate(MAGIC + "_" + UID).getEncoded());
    }

    static String getSign(String toBeSigned) throws UnrecoverableKeyException, KeyStoreException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException, UnsupportedEncodingException {
        PrivateKey privKey = (PrivateKey) mKeyStore.getKey(MAGIC + "_" + UID,
                KEYSTORE_PASS.toCharArray());

        Signature signer = Signature.getInstance("SHA256withRSA/PSS");
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                32, 1));
        signer.initSign(privKey);
        signer.update(toBeSigned.getBytes("UTF8"));
        byte[] signBytes = signer.sign();

        return Base64.getEncoder().encodeToString(signBytes);
    }

    static String getTimeStamp() {
        return TIME_STAMP_FORMAT.format(new Date()/*now*/);
    }
}
