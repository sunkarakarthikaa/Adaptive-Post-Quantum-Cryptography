/**
 * SessionResult
 * --------------
 * One row of the evaluation dataset produced by running the simulation.
 * This is deliberately structured so the CSV it feeds can go straight
 * into the paper's evaluation section (latency vs. security level vs.
 * device profile, etc). This is the seed of the "real experiments"
 * harness - extend the simulation loop (more profiles, more trials,
 * real timing distributions) to turn this into full paper-grade data.
 */
public class SessionResult {
    public final String condition; // STATIC_512 / STATIC_768 / STATIC_1024 / ADAPTIVE
    public final String deviceId;
    public final String computeTier;
    public final int batteryPercent;
    public final int linkQuality;
    public final String sensitivity;
    public final String chosenLevel;
    public final int securityRank; // 1=Kyber-512, 2=Kyber-768, 3=Kyber-1024
    public final double combinedScore;
    public final long keyGenNanos;
    public final long encapsulateNanos;
    public final long aesEncryptNanos;
    public final long decapsulateNanos;
    public final long aesDecryptNanos;
    public final int payloadBytes;
    public final int kyberCiphertextBytes;
    public final boolean roundTripCorrect;

    public SessionResult(String condition, String deviceId, String computeTier, int batteryPercent, int linkQuality,
                          String sensitivity, String chosenLevel, int securityRank, double combinedScore,
                          long keyGenNanos, long encapsulateNanos, long aesEncryptNanos,
                          long decapsulateNanos, long aesDecryptNanos,
                          int payloadBytes, int kyberCiphertextBytes, boolean roundTripCorrect) {
        this.condition = condition;
        this.deviceId = deviceId;
        this.computeTier = computeTier;
        this.batteryPercent = batteryPercent;
        this.linkQuality = linkQuality;
        this.sensitivity = sensitivity;
        this.chosenLevel = chosenLevel;
        this.securityRank = securityRank;
        this.combinedScore = combinedScore;
        this.keyGenNanos = keyGenNanos;
        this.encapsulateNanos = encapsulateNanos;
        this.aesEncryptNanos = aesEncryptNanos;
        this.decapsulateNanos = decapsulateNanos;
        this.aesDecryptNanos = aesDecryptNanos;
        this.payloadBytes = payloadBytes;
        this.kyberCiphertextBytes = kyberCiphertextBytes;
        this.roundTripCorrect = roundTripCorrect;
    }

    public static String csvHeader() {
        return "condition,deviceId,computeTier,batteryPercent,linkQuality,sensitivity,chosenLevel,securityRank,combinedScore," +
                "keyGenMicros,encapsulateMicros,aesEncryptMicros,decapsulateMicros,aesDecryptMicros," +
                "payloadBytes,kyberCiphertextBytes,roundTripCorrect";
    }

    public String toCsvRow() {
        return String.join(",",
                condition, deviceId, computeTier, String.valueOf(batteryPercent), String.valueOf(linkQuality),
                sensitivity, chosenLevel, String.valueOf(securityRank), String.format("%.3f", combinedScore),
                String.valueOf(keyGenNanos / 1000), String.valueOf(encapsulateNanos / 1000),
                String.valueOf(aesEncryptNanos / 1000), String.valueOf(decapsulateNanos / 1000),
                String.valueOf(aesDecryptNanos / 1000),
                String.valueOf(payloadBytes), String.valueOf(kyberCiphertextBytes),
                String.valueOf(roundTripCorrect));
    }
}
