#!/bin/pyhton3
from reporting.console import make_header, make_host_scan_layout, make_host_info, make_port_info
from models.port import Port
from models.host import Host


def analyse_host(host: Host, scan_result: dict, logger, console) -> Host:
    updated_host = host
    layout = make_host_scan_layout()
    layout["header"].update(make_header(host_ip=host.ip))

    # Add host information from port scan
    if host.ip in scan_result:
        host.update_host(data=scan_result[host.ip])
        ports = [Port.from_dict(port) for port in scan_result[updated_host.ip]["ports"]]
        for port in ports:
            host.add_port(port)

    layout["ports"].update(make_port_info(ports=updated_host.ports))
    layout["info"].update(make_host_info(host=updated_host))
    console.print(layout)
    return updated_host
