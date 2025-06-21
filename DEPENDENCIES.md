# Go File Dependencies

## /

| File | Dependencies |
|------|--------------|
| `appstate.go` | `appstate`, `binary`, `proto/`, `proto/`, `store`, `types`, `types/events` |
| `armadillomessage.go` | `proto`, `proto/`, `proto/`, `proto/`, `types`, `types/events` |
| `broadcast.go` | `binary`, `types` |
| `call.go` | `binary`, `types`, `types/events` |
| `client.go` | `appstate`, `binary`, `proto/`, `proto/`, `proto/`, `socket`, `store`, `types`, `types/events`, `util/keys`, `util/log` |
| `client_test.go` | `store/sqlstore`, `types/events`, `util/log` |
| `connectionevents.go` | `binary`, `store`, `types`, `types/events` |
| `download-to-file.go` | `proto/`, `util/cbcutil` |
| `download.go` | `proto/`, `proto/`, `proto/`, `proto/`, `socket`, `util/cbcutil`, `util/hkdfutil` |
| `errors.go` | `binary` |
| `group.go` | `binary`, `store`, `types`, `types/events` |
| `handshake.go` | `proto/`, `proto/`, `socket`, `util/keys` |
| `internals.go` | `appstate`, `binary`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `socket`, `store`, `types`, `types/events`, `util/keys` |
| `internals_generate.go` | - |
| `keepalive.go` | `types`, `types/events` |
| `mediaconn.go` | `binary`, `types` |
| `mediaretry.go` | `binary`, `proto/`, `types`, `types/events`, `util/gcmutil`, `util/hkdfutil` |
| `message.go` | `appstate`, `binary`, `proto/`, `proto/`, `proto/`, `store`, `types`, `types/events` |
| `msgsecret.go` | `proto/`, `proto/`, `types`, `types/events`, `util/gcmutil`, `util/hkdfutil` |
| `newsletter.go` | `binary`, `types` |
| `notification.go` | `appstate`, `binary`, `proto/`, `store`, `types`, `types/events` |
| `pair-code.go` | `binary`, `types`, `util/hkdfutil`, `util/keys` |
| `pair.go` | `binary`, `proto/`, `types`, `types/events`, `util/keys` |
| `prekeys.go` | `binary`, `types`, `util/keys` |
| `presence.go` | `binary`, `types`, `types/events` |
| `privacysettings.go` | `binary`, `types`, `types/events` |
| `push.go` | `binary`, `types` |
| `qrchan.go` | `types/events`, `util/log` |
| `receipt.go` | `binary`, `types`, `types/events` |
| `request.go` | `binary`, `types` |
| `retry.go` | `binary`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `types`, `types/events` |
| `send.go` | `binary`, `proto/`, `proto/`, `types`, `types/events` |
| `sendfb.go` | `binary`, `proto`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `types`, `types/events` |
| `update.go` | `socket`, `store` |
| `upload.go` | `socket`, `util/cbcutil` |
| `user.go` | `binary`, `proto/`, `proto/`, `types`, `types/events` |

## appstate/

| File | Dependencies |
|------|--------------|
| `appstate\decode.go` | `binary`, `proto/`, `proto/`, `store`, `util/cbcutil` |
| `appstate\encode.go` | `proto/`, `proto/`, `proto/`, `types`, `util/cbcutil` |
| `appstate\errors.go` | - |
| `appstate\hash.go` | `appstate/lthash`, `proto/`, `proto/` |
| `appstate\keys.go` | `store`, `util/hkdfutil`, `util/log` |

## appstate\lthash/

| File | Dependencies |
|------|--------------|
| `appstate\lthash\lthash.go` | `util/hkdfutil` |

## binary/

| File | Dependencies |
|------|--------------|
| `binary\attrs.go` | `types` |
| `binary\decoder.go` | `binary/token`, `types` |
| `binary\encoder.go` | `binary/token`, `types` |
| `binary\errors.go` | - |
| `binary\node.go` | `types` |
| `binary\unpack.go` | - |
| `binary\xml.go` | - |

## binary\proto/

| File | Dependencies |
|------|--------------|
| `binary\proto\doc.go` | - |
| `binary\proto\legacy.go` | `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/` |

## binary\token/

| File | Dependencies |
|------|--------------|
| `binary\token\token.go` | - |

## proto/

| File | Dependencies |
|------|--------------|
| `proto\extra.go` | `proto/`, `proto/`, `proto/`, `proto/` |

## proto\armadilloutil/

| File | Dependencies |
|------|--------------|
| `proto\armadilloutil\decode.go` | `proto/` |

## proto\waAdv/

| File | Dependencies |
|------|--------------|
| `proto\waAdv\WAAdv.pb.go` | - |

## proto\waArmadilloApplication/

| File | Dependencies |
|------|--------------|
| `proto\waArmadilloApplication\WAArmadilloApplication.pb.go` | `proto/`, `proto/` |
| `proto\waArmadilloApplication\extra.go` | - |

## proto\waArmadilloBackupCommon/

| File | Dependencies |
|------|--------------|
| `proto\waArmadilloBackupCommon\WAArmadilloBackupCommon.pb.go` | - |

## proto\waArmadilloBackupMessage/

| File | Dependencies |
|------|--------------|
| `proto\waArmadilloBackupMessage\WAArmadilloBackupMessage.pb.go` | `proto/` |

## proto\waArmadilloICDC/

| File | Dependencies |
|------|--------------|
| `proto\waArmadilloICDC\WAArmadilloICDC.pb.go` | - |

## proto\waArmadilloMiTransportAdminMessage/

| File | Dependencies |
|------|--------------|
| `proto\waArmadilloMiTransportAdminMessage\WAArmadilloMiTransportAdminMessage.pb.go` | - |

## proto\waArmadilloTransportEvent/

| File | Dependencies |
|------|--------------|
| `proto\waArmadilloTransportEvent\WAArmadilloTransportEvent.pb.go` | - |

## proto\waArmadilloXMA/

| File | Dependencies |
|------|--------------|
| `proto\waArmadilloXMA\WAArmadilloXMA.pb.go` | `proto/` |

## proto\waCert/

| File | Dependencies |
|------|--------------|
| `proto\waCert\WACert.pb.go` | - |

## proto\waChatLockSettings/

| File | Dependencies |
|------|--------------|
| `proto\waChatLockSettings\WAProtobufsChatLockSettings.pb.go` | `proto/` |

## proto\waCommon/

| File | Dependencies |
|------|--------------|
| `proto\waCommon\WACommon.pb.go` | - |
| `proto\waCommon\legacy.go` | - |

## proto\waCompanionReg/

| File | Dependencies |
|------|--------------|
| `proto\waCompanionReg\WACompanionReg.pb.go` | - |

## proto\waConsumerApplication/

| File | Dependencies |
|------|--------------|
| `proto\waConsumerApplication\WAConsumerApplication.pb.go` | `proto/` |
| `proto\waConsumerApplication\extra.go` | `proto/`, `proto/` |

## proto\waDeviceCapabilities/

| File | Dependencies |
|------|--------------|
| `proto\waDeviceCapabilities\WAProtobufsDeviceCapabilities.pb.go` | - |

## proto\waE2E/

| File | Dependencies |
|------|--------------|
| `proto\waE2E\WAWebProtobufsE2E.pb.go` | `proto/`, `proto/`, `proto/`, `proto/` |
| `proto\waE2E\legacy.go` | - |

## proto\waEphemeral/

| File | Dependencies |
|------|--------------|
| `proto\waEphemeral\WAWebProtobufsEphemeral.pb.go` | - |

## proto\waFingerprint/

| File | Dependencies |
|------|--------------|
| `proto\waFingerprint\WAFingerprint.pb.go` | - |

## proto\waHistorySync/

| File | Dependencies |
|------|--------------|
| `proto\waHistorySync\WAWebProtobufsHistorySync.pb.go` | `proto/`, `proto/`, `proto/`, `proto/`, `proto/` |
| `proto\waHistorySync\legacy.go` | - |

## proto\waLidMigrationSyncPayload/

| File | Dependencies |
|------|--------------|
| `proto\waLidMigrationSyncPayload\WAWebProtobufLidMigrationSyncPayload.pb.go` | - |

## proto\waMediaEntryData/

| File | Dependencies |
|------|--------------|
| `proto\waMediaEntryData\WAMediaEntryData.pb.go` | - |

## proto\waMediaTransport/

| File | Dependencies |
|------|--------------|
| `proto\waMediaTransport\WAMediaTransport.pb.go` | `proto/` |

## proto\waMmsRetry/

| File | Dependencies |
|------|--------------|
| `proto\waMmsRetry\WAMmsRetry.pb.go` | - |

## proto\waMsgApplication/

| File | Dependencies |
|------|--------------|
| `proto\waMsgApplication\WAMsgApplication.pb.go` | `proto/` |
| `proto\waMsgApplication\extra.go` | `proto/`, `proto/`, `proto/`, `proto/` |

## proto\waMsgTransport/

| File | Dependencies |
|------|--------------|
| `proto\waMsgTransport\WAMsgTransport.pb.go` | `proto/` |
| `proto\waMsgTransport\extra.go` | `proto/`, `proto/` |

## proto\waMultiDevice/

| File | Dependencies |
|------|--------------|
| `proto\waMultiDevice\WAMultiDevice.pb.go` | - |
| `proto\waMultiDevice\extra.go` | - |

## proto\waQuickPromotionSurfaces/

| File | Dependencies |
|------|--------------|
| `proto\waQuickPromotionSurfaces\WAWebProtobufsQuickPromotionSurfaces.pb.go` | - |

## proto\waReporting/

| File | Dependencies |
|------|--------------|
| `proto\waReporting\WAWebProtobufsReporting.pb.go` | - |

## proto\waRoutingInfo/

| File | Dependencies |
|------|--------------|
| `proto\waRoutingInfo\WAWebProtobufsRoutingInfo.pb.go` | - |

## proto\waServerSync/

| File | Dependencies |
|------|--------------|
| `proto\waServerSync\WAServerSync.pb.go` | - |
| `proto\waServerSync\legacy.go` | - |

## proto\waSyncAction/

| File | Dependencies |
|------|--------------|
| `proto\waSyncAction\WASyncAction.pb.go` | `proto/`, `proto/`, `proto/` |

## proto\waUserPassword/

| File | Dependencies |
|------|--------------|
| `proto\waUserPassword\WAProtobufsUserPassword.pb.go` | - |

## proto\waVnameCert/

| File | Dependencies |
|------|--------------|
| `proto\waVnameCert\WAWebProtobufsVnameCert.pb.go` | - |

## proto\waWa6/

| File | Dependencies |
|------|--------------|
| `proto\waWa6\WAWebProtobufsWa6.pb.go` | - |

## proto\waWeb/

| File | Dependencies |
|------|--------------|
| `proto\waWeb\WAWebProtobufsWeb.pb.go` | `proto/`, `proto/` |
| `proto\waWeb\legacy.go` | - |

## proto\waWinUIApi/

| File | Dependencies |
|------|--------------|
| `proto\waWinUIApi\WAWinUIApi.pb.go` | - |

## socket/

| File | Dependencies |
|------|--------------|
| `socket\constants.go` | `binary/token` |
| `socket\framesocket.go` | `util/log` |
| `socket\noisehandshake.go` | `util/gcmutil` |
| `socket\noisesocket.go` | - |

## store/

| File | Dependencies |
|------|--------------|
| `store\clientpayload.go` | `proto/`, `proto/`, `types` |
| `store\noop.go` | `types`, `util/keys` |
| `store\signal.go` | - |
| `store\store.go` | `proto/`, `types`, `util/keys`, `util/log` |

## store\sqlstore/

| File | Dependencies |
|------|--------------|
| `store\sqlstore\container.go` | `proto/`, `store`, `store/sqlstore/upgrades`, `types`, `util/keys`, `util/log` |
| `store\sqlstore\lidmap.go` | `store`, `types` |
| `store\sqlstore\store.go` | `store`, `types`, `util/keys` |

## store\sqlstore\upgrades/

| File | Dependencies |
|------|--------------|
| `store\sqlstore\upgrades\upgrades.go` | - |

## types/

| File | Dependencies |
|------|--------------|
| `types\botmap.go` | - |
| `types\call.go` | - |
| `types\group.go` | - |
| `types\jid.go` | - |
| `types\message.go` | - |
| `types\newsletter.go` | `proto/` |
| `types\presence.go` | - |
| `types\user.go` | `proto/` |

## types\events/

| File | Dependencies |
|------|--------------|
| `types\events\appstate.go` | `appstate`, `proto/`, `types` |
| `types\events\call.go` | `binary`, `types` |
| `types\events\events.go` | `binary`, `proto`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `proto/`, `types` |

## util\cbcutil/

| File | Dependencies |
|------|--------------|
| `util\cbcutil\cbc.go` | - |

## util\gcmutil/

| File | Dependencies |
|------|--------------|
| `util\gcmutil\gcm.go` | - |

## util\hkdfutil/

| File | Dependencies |
|------|--------------|
| `util\hkdfutil\hkdf.go` | - |

## util\keys/

| File | Dependencies |
|------|--------------|
| `util\keys\keypair.go` | - |

## util\log/

| File | Dependencies |
|------|--------------|
| `util\log\log.go` | - |
| `util\log\zerolog.go` | - |
