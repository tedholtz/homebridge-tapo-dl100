import {
  API, DynamicPlatformPlugin, Logger, PlatformAccessory, PlatformConfig, Service, Characteristic,
} from 'homebridge';
import { PLATFORM_NAME, PLUGIN_NAME } from './settings';
import { DlklapApi, DlklapConfig } from './dlklapApi';
import { LockAccessory } from './lockAccessory';

interface LockConfigEntry {
  name: string;
  ip: string;
  cloudUsername: string;
  cloudPassword: string;
  pollSeconds?: number;
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
      if (!lock.ip || !lock.cloudUsername || !lock.cloudPassword) {
        this.log.warn(`Skipping lock "${lock.name}": missing required config (ip, cloudUsername, cloudPassword).`);
        continue;
      }
      // Use lock name as the UUID seed (deviceId is resolved at runtime, not from config).
      const uuid = this.api.hap.uuid.generate(`tapo-dl100-${lock.name}`);
      let accessory = this.accessories.find((a) => a.UUID === uuid);
      if (!accessory) {
        accessory = new this.api.platformAccessory(lock.name, uuid);
        this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
      }

      // Seed runtime identifiers from cached accessory context (populated on first successful connect).
      const cfg: DlklapConfig = {
        ip: lock.ip,
        cloudUsername: lock.cloudUsername,
        cloudPassword: lock.cloudPassword,
        _terminalUUID: accessory.context.terminalUUID,
        _deviceId: accessory.context.deviceId,
      };

      const dl = new DlklapApi(cfg, {
        debug: (m) => this.log.debug(m),
        warn: (m) => this.log.warn(m),
        error: (m) => this.log.error(m),
      }, lock.name);

      // After the first successful operation, persist the resolved identifiers so subsequent
      // restarts skip the cloud device-list call.
      const persistResolved = () => {
        const tid = dl.resolvedTerminalUUID;
        const did = dl.resolvedDeviceId;
        if (tid && did && (accessory!.context.terminalUUID !== tid || accessory!.context.deviceId !== did)) {
          accessory!.context.terminalUUID = tid;
          accessory!.context.deviceId = did;
          this.api.updatePlatformAccessories([accessory!]);
          this.log.debug(`Persisted deviceId=${did} and terminalUUID=${tid} to accessory context.`);
        }
      };

      new LockAccessory(this, accessory, dl, (lock.pollSeconds ?? 300) * 1000, persistResolved);
    }
  }
}
