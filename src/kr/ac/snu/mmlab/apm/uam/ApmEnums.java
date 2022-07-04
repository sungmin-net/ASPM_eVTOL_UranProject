package kr.ac.snu.mmlab.apm.uam;

//Note. This class must be same with kr.ac.snu.mmlab.apm.controlcenter.ApmEnums

public class ApmEnums {
    public static enum Payload {
        Magic,
        Signed,
        Signature,  // for broadcast message
        Cert,
    }

    public static enum Signed {
        Issuer,
        TimeStamp, // yyMMddHHmmss
        CurPolicyVer, // yyMMddHHmmss
        ServInfo // optional, IP address + ":" + port number
    }

    public static enum Policy {
        Issuer,
        Version,
        Target,
        Begin,
        Until,
        Latitude,
        Longitude,
        Altitude,
        Radius,
        Restriction
    }

    public static enum Manifest {
        Metadata,
        Signature // for manifest
    }

    public static enum Metadata {
        Version,
        Fingerprint,
        PrevVersion,
        PrevFingerprint
    }

    public static enum Restriction {
        SetCameraDisabled,
        SetMasterVolumeMuted,
        SetUamWindowBlurred
    }

    public static enum Request {
        Magic,
        RsaEnc,
        KeyAlias
    }

    public static enum RsaEnc {
        UserId,
        Version,
        Command,
        Nonce,
    }

    public static enum Response {
        Magic,
        Regulation,
        Signature,
    }

    public static enum Regulation {
        Version,
        Nonce,
        Restriction
    }

    public static enum Command {
        Hello,
        Start,
        Stop
    }
}
