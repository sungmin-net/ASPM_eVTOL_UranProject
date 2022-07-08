package kr.ac.snu.mmlab.apm.uam;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONObject;

import kr.ac.snu.mmlab.apm.uam.ApmEnums.*;

public class ApmUamServerMain {

    private static final String UID = "UAM2";
    private static final String VERSION = "0.1"; // TODO make schema
    private static final String MAGIC = "APM";
    private static final String POLICY_DIR_PREFIX = MAGIC + "_P";
    private static final String KEYSTORE_PASS = "mmlabmmlab"; // TODO apply timestamp based HMAC protection
    private static final int TLS_PORT = 9999;
    static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyMMddHHmmss");

    private static KeyStore mKeyStore;
    private static long mLastApmPolicyVer = 0;  // default
    private static String mLastApmPolicyFingerprint = "0";
    private static Map<String /* target */, Map<String /* restriction */, Term>> mRegulation;

    private static boolean mIsServing;

    // current position
    private static double mLatitude = 0.0;
    private static double mLongitude = 0.0;
    private static double mAltitude = 400.0;

    static Thread mApmUamServer = new Thread(new Runnable() {

        @Override
        public void run() {

            System.out.println("# " + UID + " APM server is starting.");
            mIsServing = true;
            SSLServerSocket servSock = null;

            try {
                SSLServerSocketFactory sslServSockFactory =
                        (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                servSock = (SSLServerSocket) sslServSockFactory.createServerSocket(TLS_PORT);
                System.out.println("# Wait for client request");

                while (mIsServing) {
                    SSLSocket sock = (SSLSocket) servSock.accept();
                    new Thread(new Worker(sock)).start();
                }

            } catch (IOException e) {
                e.printStackTrace();
                mIsServing = false;
                System.out.println("# Server stopped.");
                if (servSock != null & !servSock.isClosed()) {
                    try {
                        servSock.close();
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                }
            } finally {
                if (servSock != null & !servSock.isClosed()) {
                    try {
                        servSock.close();
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                }
            }
        }

        class Worker implements Runnable {

            private SSLSocket mSocket;

            public Worker(SSLSocket socket) {
                mSocket = socket;
            }

            @Override
            public void run() {
                try {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(
                            mSocket.getInputStream()));
                    BufferedWriter bw = new BufferedWriter(
                            new OutputStreamWriter(mSocket.getOutputStream()));
                    PrintWriter writer = new PrintWriter(bw, true);
                    String clientMsg = reader.readLine();

                    System.out.println("# Rcvd " + mSocket.getInetAddress() + ": " + clientMsg);

                    String serverMsg = null;
                    if (clientMsg != null && clientMsg.startsWith("Hello!")) { // for TLS echo test
                        serverMsg = "[Server echo] " + clientMsg;
                    } else {
                        serverMsg = getServerReply(clientMsg);
                    }

                    if (serverMsg != null) {
                        writer.println(serverMsg);
                        System.out.println("# Sent " + mSocket.getInetAddress() + ": " + serverMsg);
                        writer.flush();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            private String getServerReply(String clientMsg) throws Exception {

                // 0. parameter sanity check.
                if (clientMsg == null || "".equals(clientMsg)) {
                    System.out.println("# Client message is null or empty.");
                    return null;
                }

                System.out.println(clientMsg);

                JSONObject clientJson = new JSONObject(clientMsg);

                // 1. check magic.
                String clientMagic = clientJson.getString(Request.Magic.toString());
                if (!MAGIC.equals(clientMagic)) {
                    return null;
                }

                // 2. check key alias
                String clientKeyAlias = clientJson.getString(Request.KeyAlias.toString());
                if (!(MAGIC + "_" + UID).equals(clientKeyAlias)) {
                    return null;
                }

                // 3. decrypt client request
                String clientRsaEnc = clientJson.getString(Request.RsaEnc.toString());
                JSONArray plainJsonArray = new JSONArray(decryptRsa(clientRsaEnc, clientKeyAlias));

                System.out.println("# Decrypted " + plainJsonArray.toString());

                String clientUID = plainJsonArray.getJSONObject(RsaEnc.UserId.ordinal())
                        .getString(RsaEnc.UserId.toString());
                String clientVersion = plainJsonArray.getJSONObject(RsaEnc.Version.ordinal())
                        .getString(RsaEnc.Version.toString());
                String clientCmd = plainJsonArray.getJSONObject(RsaEnc.Command.ordinal())
                        .getString(RsaEnc.Command.toString());
                if (!Command.Start.toString().equals(clientCmd)) {
                    return null;
                }
                String clientNonce = plainJsonArray.getJSONObject(RsaEnc.Nonce.ordinal())
                        .getString(RsaEnc.Nonce.toString());
                JSONObject servJson = new JSONObject();
                servJson.put(Response.Magic.toString(), MAGIC);

                refreshRegulation();

                JSONArray regulation = new JSONArray();
                regulation.put(new JSONObject().put(Regulation.Version.toString(), VERSION));
                regulation.put(new JSONObject().put(Regulation.Nonce.toString(), clientNonce));
                regulation.put(new JSONObject().put(Regulation.Restriction.toString(),
                        getRestrictions(clientUID, clientVersion)));

                servJson.put(Response.Regulation.toString(), regulation);
                servJson.put(Response.Signature.toString(),
                        getSign(regulation.toString(), clientKeyAlias));

                return servJson.toString();
            }

            private String getSign(String toBeSigned, String keyAlias) throws Exception {
                PrivateKey privKey = (PrivateKey) mKeyStore.getKey(keyAlias,
                        KEYSTORE_PASS.toCharArray());
                Signature signer = Signature.getInstance("RSASSA-PSS");
                signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                        MGF1ParameterSpec.SHA256, 32, 1));
                signer.initSign(privKey);
                signer.update(toBeSigned.getBytes("UTF-8"));

                return Base64.getEncoder().encodeToString(signer.sign());
            }

            private JSONArray getRestrictions(String clientUID, String clientVersion)
                    throws Exception {

                // Note. In prototype, clientVersion is 0.1 which is same with server version then
                // don't care. But in real-world, restriction list can vary up to client version.

                JSONArray ret = new JSONArray();

                Map<String, Term> defaultRestrictionMap = mRegulation.get("ALL");
                Map<String, Term> targetRestrictionMap = mRegulation.get(clientUID);

                if (defaultRestrictionMap != null) {
                    for (Restriction r : Restriction.values()) {

                        Term curTerm = null;
                        Term defaultTerm = defaultRestrictionMap.get(r.toString());
                        if (defaultTerm != null && isValidTerm(defaultTerm)) {
                            curTerm = defaultTerm;
                        }

                        Term targetTerm = null;
                        if (targetRestrictionMap != null) {
                            targetTerm = targetRestrictionMap.get(r.toString());
                        }

                        if (targetTerm != null && isValidTerm(targetTerm)) {
                            curTerm = targetTerm;
                        }

                        if (curTerm != null) {
                            ret.put(new JSONObject().put(r.toString(), curTerm.enforced));
                        }
                    }
                }

                return ret;
            }

            private boolean isValidTerm(Term curTerm) throws ParseException {

                // 1. check timing condition
                long now = Long.parseLong(TIME_FORMAT.format(new Date()));
                long begin = Long.parseLong(curTerm.begin);
                long until = Long.parseLong(curTerm.until);

                if (now < begin || until < now) {
                    return false;
                }

                // 2. check positioning condition
                double distance = Math.sqrt(Math.pow(curTerm.latitude - mLatitude, 2)
                        + Math.pow(curTerm.latitude - mLatitude, 2)
                        + Math.pow(curTerm.longitude - mLongitude, 2)
                        + Math.pow(curTerm.altitude - mAltitude, 2));
                if (distance > curTerm.radius) {
                    System.out.println("# Distance: " + distance);
                    System.out.println("# Radius: " + curTerm.radius);
                    return false;
                }

                return true;
            }

            private String decryptRsa(String clientRsaEnc, String keyAlias) throws Exception {
                byte[] cipherBytes = Base64.getDecoder().decode(clientRsaEnc);
                PrivateKey privKey = (PrivateKey) mKeyStore.getKey(keyAlias,
                        KEYSTORE_PASS.toCharArray());
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding");
                cipher.init(Cipher.DECRYPT_MODE, privKey);
                byte[] decryptedBytes = cipher.doFinal(cipherBytes);
                return new String(decryptedBytes);
            }
        }
    });

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        loadKeystore();
        System.setProperty("javax.net.ssl.keyStore", MAGIC + "_" + UID + ".p12");
        System.setProperty("javax.net.ssl.keyStorePassword", KEYSTORE_PASS);

        mRegulation = new HashMap<>();
        refreshRegulation();
        printRegulation();

        mApmUamServer.start();
    }


    private static void refreshRegulation() throws Exception {
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

        for (String fileName : fileNameList) {
            String curVer = fileName.replace(POLICY_DIR_PREFIX, "");
            long curVerLong = Long.parseLong(curVer);
            if (mLastApmPolicyVer != 0 && mLastApmPolicyVer >= curVerLong) {
                // ignore old versions if it is not first call
                continue;
            }

            // Note. policy signature, fingerprint, and chain were verified when Node received.
            // See ApmUamNodeMain.isNewApmPolicyVerified()

            // load policy
            JSONArray curPolicy = new JSONArray(new String(Files.readAllBytes(Paths.get(
                    POLICY_DIR_PREFIX + curVer + File.separator + "policy.json"))));

            String curIssuer = curPolicy.getJSONObject(Policy.Issuer.ordinal()).getString(
                    Policy.Issuer.toString());
            String curIssued = curVer;
            String curBegin = curPolicy.getJSONObject(Policy.Begin.ordinal()).getString(
                    Policy.Begin.toString());
            String curUntil = curPolicy.getJSONObject(Policy.Until.ordinal()).getString(
                    Policy.Until.toString());
            double curLatitude = curPolicy.getJSONObject(Policy.Latitude.ordinal()).getDouble(
                    Policy.Latitude.toString());
            double curLongitude = curPolicy.getJSONObject(Policy.Longitude.ordinal()).getDouble(
                    Policy.Longitude.toString());
            double curAltitude = curPolicy.getJSONObject(Policy.Altitude.ordinal()).getDouble(
                    Policy.Altitude.toString());
            double curRadius = curPolicy.getJSONObject(Policy.Radius.ordinal()).getDouble(
                    Policy.Radius.toString());

            JSONArray targetArr = curPolicy.getJSONObject(Policy.Target.ordinal()).getJSONArray(
                    Policy.Target.toString());

            JSONArray restrictionArr = curPolicy.getJSONObject(
                    Policy.Restriction.ordinal()).getJSONArray(Policy.Restriction.toString());

            // parse policy to regulation
            for (Object target : targetArr) {
                String curTarget = (String) target;

                Map<String /*restriction*/ , Term> curTargetMap = null;
                if (mRegulation.containsKey(curTarget)) {
                    curTargetMap = mRegulation.get(curTarget);
                } else {
                    curTargetMap = new HashMap<>();
                }

                for (Object restrictionObj: restrictionArr) {
                    JSONObject curRestriction = (JSONObject) restrictionObj;
                    for (Restriction r : Restriction.values()) {
                        if (curRestriction.has(r.toString())) {
                            Object enforced = curRestriction.get(r.toString());
                            Term restrictionTerm = new Term();
                            restrictionTerm.enforced = enforced;
                            restrictionTerm.issuer = curIssuer;
                            restrictionTerm.issued = curIssued;
                            restrictionTerm.begin = curBegin;
                            restrictionTerm.until = curUntil;
                            restrictionTerm.latitude = curLatitude;
                            restrictionTerm.longitude = curLongitude;
                            restrictionTerm.altitude = curAltitude;
                            restrictionTerm.radius = curRadius;

                            curTargetMap.put(r.toString(), restrictionTerm);
                        }
                    }
                }
                mRegulation.put(curTarget, curTargetMap);

            }
            System.out.println("# APPLIED: " + curVer);
            mLastApmPolicyVer = curVerLong;
        }
    }


    private static void printRegulation() {
        System.out.println("# Current APM policy is the below.");
        for (String target : mRegulation.keySet()) {
            System.out.println("* Target: " + target);
            Map<String, Term> targetMap = mRegulation.get(target);
            for (String restriction : targetMap.keySet()) {
                System.out.print(restriction);
                System.out.println(targetMap.get(restriction));
            }
        }
    }


    static void loadKeystore() throws Exception {
        mKeyStore = KeyStore.getInstance("PKCS12");
        FileInputStream fis = new FileInputStream(new File(MAGIC + "_" + UID + ".p12"));
        mKeyStore.load(fis, KEYSTORE_PASS.toCharArray());
    }

    static class Term {
        Object enforced; // This can vary like true(or false), a range, or a string.
        String issuer;
        String issued;
        String begin;
        String until;
        double latitude;
        double longitude;
        double altitude;
        double radius;

        @Override
        public String toString() {
            StringBuffer buf = new StringBuffer();
            buf.append("- enforced: ").append(String.valueOf(enforced)).append("\n");
            buf.append("- issuer: ").append(issuer).append("\n");
            buf.append("- issued: ").append(issued).append("\n");
            buf.append("- begin: ").append(begin).append("\n");
            buf.append("- until: ").append(until).append("\n");
            buf.append("- latitude: ").append(latitude).append("\n");
            buf.append("- longitude: ").append(longitude).append("\n");
            buf.append("- altitude: ").append(altitude).append("\n");
            buf.append("- radius: ").append(radius);

            return buf.toString();
        }
    }
}