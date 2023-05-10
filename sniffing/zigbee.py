import itertools

from zigpy_znp.tools.network_scan import scan_once
import zigpy_znp.types as t
import zigpy_znp.commands as c
from zigpy_znp.api import ZNP
from zigpy_znp.config import CONFIG_SCHEMA
from zigpy_znp.types.nvids import OsalNvIds
from rich.progress import Progress


async def network_scan(
        znp: ZNP, channels: t.Channels, num_scans: int, duration_exp: int, duplicates: bool, logger
) -> dict[str, list]:

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

        with Progress() as scanner:
            scan_task = scanner.add_task(f"Scanning for ZigBee beacons...", total=num_scans)

            for i in itertools.count(start=1):
                if num_scans is not None and i > num_scans:
                    break

                async for beacon in scan_once(znp, channels, duration_exp):
                    if not duplicates:
                        key = beacon.ExtendedPanId
                        if key in seen_beacons:
                            continue
                        seen_beacons.add(key)
                    logger.info(f"Discovered beacon on channel {beacon.Channel} with PAN ID: {beacon.PanId}")
                    beacons.setdefault(beacon.Channel, []).append(beacon.as_dict())
                scanner.advance(task_id=scan_task, advance=1)
    finally:
        if previous_nib is not None:
            await znp.nvram.osal_write(OsalNvIds.NIB, previous_nib, create=True)

        await znp.nvram.osal_write(OsalNvIds.CHANLIST, previous_channels)
        znp.close()
        return beacons


async def discover_zigbee_routers(logger, radio_path: str, num_scans=6) -> dict[str, list]:
    znp = ZNP(CONFIG_SCHEMA({"device": {"path": radio_path}}))
    await znp.connect()
    channels = t.Channels.from_channel_list(map(int, [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]))

    scan = await network_scan(
        duplicates=False,
        duration_exp=4,
        num_scans=num_scans,
        channels=channels,
        znp=znp,
        logger=logger
    )
    znp.close()
    return scan
