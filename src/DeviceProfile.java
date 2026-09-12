/**
 * DeviceProfile
 * --------------
 * Represents the resource/context profile of a simulated IoT device.
 * This is the INPUT to the Policy Engine - in a real deployment these
 * values would come from actual device telemetry (battery API, network
 * stack RTT measurements, a data-classification tag set by the
 * application layer, etc). Here they are simulated for controlled,
 * repeatable experiments.
 *
 * batteryPercent   : 0-100, simulated remaining battery
 * computeTier      : LOW / MEDIUM / HIGH, simulated CPU class
 *                    (e.g. LOW ~ 8-bit MCU class, HIGH ~ Cortex-A gateway class)
 * linkQuality      : 0-100, simulated network link quality (lower = lossier/slower link)
 * dataSensitivity  : LOW / MEDIUM / HIGH, application-assigned sensitivity of payload
 */
public class DeviceProfile {

    public enum ComputeTier { LOW, MEDIUM, HIGH }
    public enum Sensitivity { LOW, MEDIUM, HIGH }

    private final String deviceId;
    private final int batteryPercent;
    private final ComputeTier computeTier;
    private final int linkQuality;
    private final Sensitivity dataSensitivity;

    public DeviceProfile(String deviceId, int batteryPercent, ComputeTier computeTier,
                          int linkQuality, Sensitivity dataSensitivity) {
        this.deviceId = deviceId;
        this.batteryPercent = batteryPercent;
        this.computeTier = computeTier;
        this.linkQuality = linkQuality;
        this.dataSensitivity = dataSensitivity;
    }

    public String getDeviceId() { return deviceId; }
    public int getBatteryPercent() { return batteryPercent; }
    public ComputeTier getComputeTier() { return computeTier; }
    public int getLinkQuality() { return linkQuality; }
    public Sensitivity getDataSensitivity() { return dataSensitivity; }

    @Override
    public String toString() {
        return String.format("Device[%s] battery=%d%% compute=%s link=%d%% sensitivity=%s",
                deviceId, batteryPercent, computeTier, linkQuality, dataSensitivity);
    }
}
