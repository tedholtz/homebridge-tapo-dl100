import {
  API, DynamicPlatformPlugin, Logger, PlatformAccessory, PlatformConfig, Service, Characteristic,
} from 'homebridge';
import { PLATFORM_NAME, PLUGIN_NAME } from './settings';
import { DlklapApi, DlklapConfig } from './dlklapApi';
import { LockAccessory } from './lockAccessory';

interface LockConfigEntry extends DlklapConfig {
  name: string;
  pollSeconds?: number;
  autoLockSeconds?: number;   // fallback if device doesn't report auto_lock_time; 0 = unknown
}

export class TapoDL100Platform implements DynamicPlatformPlugin {
  public readonly Service: typeof Service = this.api.hap.Service;
  public readonly Characteristic: typeof Characteristic = this.api.hap.Characteristic;
  public readonly accessories: PlatformAccessory[] = [];

  constructor(
    public readonly log: Logger,
    public readonly config: PlatformConfig,
    public readonly api: API,
  ) {
    this.api.on('didFinishLaunching', () => this.discover());
  }

  configureAccessory(accessory: PlatformAccessory): void {
    this.accessories.push(accessory);
  }

  private discover(): void {
    const locks: LockConfigEntry[] = (this.config.locks as LockConfigEntry[]) ?? [];
    for (const lock of locks) {
      if (!lock.ip || !lock.deviceId || !lock.cloudUsername || !lock.cloudPassword || !lock.terminalUUID) {
        this.log.warn(`Skipping lock "${lock.name}": missing required config.`);
        continue;
      }
      const uuid = this.api.hap.uuid.generate(`tapo-dl100-${lock.deviceId}`);
      let accessory = this.accessories.find((a) => a.UUID === uuid);
      if (!accessory) {
        accessory = new this.api.platformAccessory(lock.name, uuid);
        accessory.context.deviceId = lock.deviceId;
        this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
      }
      const dl = new DlklapApi(lock, {
        debug: (m) => this.log.debug(m),
        warn: (m) => this.log.warn(m),
        error: (m) => this.log.error(m),
      });
      new LockAccessory(this, accessory, dl, (lock.pollSeconds ?? 300) * 1000, lock.autoLockSeconds ?? 0);
    }
  }
}
