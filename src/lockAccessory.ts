import { PlatformAccessory, Service, CharacteristicValue } from 'homebridge';
import { TapoDL100Platform } from './platform';
import { DlklapApi, DeviceInfo } from './dlklapApi';

export class LockAccessory {
  private lockService: Service;
  private batteryService: Service;
  private info?: DeviceInfo;
  private lastFetch = 0;

  constructor(
    private readonly platform: TapoDL100Platform,
    private readonly accessory: PlatformAccessory,
    private readonly api: DlklapApi,
    private readonly pollMs: number,
  ) {
    const { Service: S, Characteristic: C } = this.platform;

    this.accessory.getService(S.AccessoryInformation)!
      .setCharacteristic(C.Manufacturer, 'TP-Link Tapo')
      .setCharacteristic(C.Model, 'DL100')
      .setCharacteristic(C.SerialNumber, accessory.context.deviceId ?? 'DL100');

    this.lockService = this.accessory.getService(S.LockMechanism)
      ?? this.accessory.addService(S.LockMechanism, accessory.displayName);
    this.lockService.getCharacteristic(C.LockCurrentState).onGet(() => this.getCurrent());
    this.lockService.getCharacteristic(C.LockTargetState)
      .onGet(() => this.getTarget())
      .onSet((v) => this.setTarget(v));

    this.batteryService = this.accessory.getService(S.Battery)
      ?? this.accessory.addService(S.Battery, `${accessory.displayName} Battery`);
    this.batteryService.getCharacteristic(C.BatteryLevel).onGet(() => this.info?.battery_percentage ?? 100);
    this.batteryService.getCharacteristic(C.StatusLowBattery).onGet(() => (this.info?.at_low_battery ? 1 : 0));

    void this.refresh();
    setInterval(() => void this.refresh(), pollMs);
  }

  private mapCurrent(lockStatus?: number): CharacteristicValue {
    const C = this.platform.Characteristic.LockCurrentState;
    switch (lockStatus) {
      case 1: return C.UNSECURED;   // lock_status 1 = bolt retracted = unlocked
      case 0: return C.SECURED;     // lock_status 0 = bolt extended = locked
      case 3: case 4: return C.JAMMED;
      default: return C.UNKNOWN;
    }
  }

  private refreshing?: Promise<void>;
  private refresh(): Promise<void> {
    // Coalesce concurrent refreshes (HAP polling + interval + post-set) into one.
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.doRefresh().finally(() => { this.refreshing = undefined; });
    return this.refreshing;
  }

  private async doRefresh(): Promise<void> {
    try {
      const C = this.platform.Characteristic;
      this.info = await this.api.getDeviceInfo();
      this.lastFetch = Date.now();
      this.lockService.updateCharacteristic(C.LockCurrentState, this.mapCurrent(this.info.lock_status));
      if (this.info.lock_status === 0 || this.info.lock_status === 1) {
        this.lockService.updateCharacteristic(C.LockTargetState,
          this.info.lock_status === 1 ? C.LockTargetState.SECURED : C.LockTargetState.UNSECURED);
      }
      this.batteryService.updateCharacteristic(C.BatteryLevel, this.info.battery_percentage ?? 100);
      this.batteryService.updateCharacteristic(C.StatusLowBattery, this.info.at_low_battery ? 1 : 0);
    } catch (e) {
      this.platform.log.debug(`refresh failed: ${(e as Error).message}`);
    }
  }

  private getCurrent(): CharacteristicValue {
    // Never block the HomeKit read: return cached state, refresh in background.
    if (!this.info || Date.now() - this.lastFetch > this.pollMs) void this.refresh();
    return this.mapCurrent(this.info?.lock_status);
  }

  private getTarget(): CharacteristicValue {
    const T = this.platform.Characteristic.LockTargetState;
    return this.info?.lock_status === 0 ? T.SECURED : T.UNSECURED;  // 0 = bolt out = locked
  }

  private async setTarget(value: CharacteristicValue): Promise<void> {
    const T = this.platform.Characteristic.LockTargetState;
    const locked = value === T.SECURED;
    this.platform.log.info(`Setting lock -> ${locked ? 'SECURED' : 'UNSECURED'}`);
    await this.api.setLock(locked);
    await new Promise((r) => setTimeout(r, 3000));   // let the bolt move
    await this.refresh();
  }
}
