import asyncio
import itertools
import json

import zigpy_znp.types as t
import zigpy_znp.commands as c
from zigpy_znp.api import ZNP
from zigpy_znp.config import CONFIG_SCHEMA
from zigpy_znp.types.nvids import OsalNvIds


async def scan_once(znp: ZNP, channels: t.Channels, duration_exp: int):
    async with znp.capture_responses(
        [
            c.ZDO.BeaconNotifyInd.Callback(partial=True),
            c.ZDO.NwkDiscoveryCnf.Callback(partial=True),
        ]
    ) as updates:
        await znp.request(
            c.ZDO.NetworkDiscoveryReq.Req(
                Channels=channels,
                ScanDuration=duration_exp,
            ),
            RspStatus=t.Status.SUCCESS,
        )

        while True:
            update = await updates.get()

            if isinstance(update, c.ZDO.NwkDiscoveryCnf.Callback):
                break

            for beacon in update.Beacons:
                yield beacon


async def network_scan(
    znp: ZNP, channels: t.Channels, num_scans: int, duration_exp: int, duplicates: bool
) -> dict:
    if znp.version == 1.2:
        previous_nib = await znp.nvram.osal_read(OsalNvIds.NIB, item_type=t.NIB)
        await znp.nvram.osal_delete(OsalNvIds.NIB)
    else:
        previous_nib = None

    previous_channels = await znp.nvram.osal_read(
        OsalNvIds.CHANLIST, item_type=t.Channels
    )
    await znp.nvram.osal_write(OsalNvIds.CHANLIST, t.Channels.ALL_CHANNELS)
    beacons = {}
    try:
        await znp.request_callback_rsp(
            request=c.SYS.ResetReq.Req(Type=t.ResetType.Soft),
            callback=c.SYS.ResetInd.Callback(partial=True),
        )

        seen_beacons = set()

        for i in itertools.count(start=1):
            if num_scans is not None and i > num_scans:
                break

            async for beacon in scan_once(znp, channels, duration_exp):
                if not duplicates:
                    key = beacon.replace(Depth=0, LQI=0).serialize()
                    if key in seen_beacons:
                        continue
                    seen_beacons.add(key)
                print(beacon.asdict)
                beacons[beacon.src] = {
                    "extended_pan_id": beacon.PanId,
                    "pan_id": beacon.PanId,
                    "channel": f"{beacon.Channel:2>}",
                    "permit_joins": beacon.PermitJoining,
                    "router_capacity": beacon.RouterCapacity,
                    "device_capacity": beacon.DeviceCapacity,
                    "protocol_version": beacon.ProtocolVersion,
                    "stack_profile": beacon.StackProfile,
                    "depth": f"{beacon.Depth:>3}",
                    "update_id": f"{beacon.UpdateId:>2}",
                    "lqi": f"{beacon.LQI:>3}"
                }

    finally:
        if previous_nib is not None:
            await znp.nvram.osal_write(OsalNvIds.NIB, previous_nib, create=True)

        await znp.nvram.osal_write(OsalNvIds.CHANLIST, previous_channels)
        znp.close()
        return beacons


async def discover_zigbee_routers(radio_path: str, num_scans=None):
    znp = ZNP(CONFIG_SCHEMA({"device": {"path": radio_path}}))
    await znp.connect()
    channels = t.Channels.from_channel_list(map(int, [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]))
    scan = await network_scan(
        duplicates=False,
        duration_exp=10,
        num_scans=num_scans,
        channels=channels,
        znp=znp
    )
    print(json.dumps(scan, indent=4))
    znp.close()


path = "/dev/ttyACM0"
asyncio.run(discover_zigbee_routers(radio_path=path))
