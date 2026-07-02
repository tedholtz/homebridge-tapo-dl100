// src/index.ts
import { API } from 'homebridge';
import { PLATFORM_NAME } from './settings';
import { TapoDL100Platform } from './platform';

export = (api: API) => {
  api.registerPlatform(PLATFORM_NAME, TapoDL100Platform);
};
