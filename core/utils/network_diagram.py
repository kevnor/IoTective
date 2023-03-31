import json
from core.utils.host import get_default_gateway
import networkx as nx
import plotly.graph_objects as go
from N2G import yed_diagram


def plot_topology(path):
    with open(path, "r") as file:
        json_file = json.loads(file.read())
        if json_file["hosts"]["ip_network"] is not None:
            network = json_file["hosts"]["ip_network"]

    gateway = get_default_gateway()
    diagram = yed_diagram()
    graph = {
        'nodes': [],
        'links': []
    }

    for host in network:
        ports = []
        for prt in network[host]['ports']:
            ports.append(prt)
        graph['nodes'].append({
            'id': host,
            'label': f'Open ports: {str(ports)}',
            'top_label': host
        })

    for node in graph['nodes']:
        if node['id'] == gateway:
            continue
        graph['links'].append({
            'source': gateway,
            'target': node['id']
        })

    diagram.from_dict(graph)
    diagram.layout(algo="kk")
    diagram.dump_file(filename="test_graph.graphml", folder="./")


def create_network_diagram(path):
    with open(path, "r") as file:
        json_file = json.loads(file.read())
        if json_file["hosts"]["ip_network"] is not None:
            network = json_file["hosts"]["ip_network"]

    gateway = get_default_gateway()
    G = nx.DiGraph()

    for host in network:
        ports = []
        for prt in network[host]['ports']:
            ports.append(prt)
        G.add_node(host, ports=ports)

    pos = nx.random_layout(G)

    for node in G.nodes():
        if node == gateway:
            continue
        G.add_edge(node, gateway)

    # create edge traces
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]][0], pos[edge[0]][1]
        x1, y1 = pos[edge[1]][0], pos[edge[1]][1]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1, color='gray'),
        hoverinfo='none',
        mode='lines'
    )

    # create node trace
    node_x = []
    node_y = []
    node_text = []
    node_ports = []
    for node in G.nodes():
        node_x.append(pos[node][0])
        node_y.append(pos[node][1])
        node_text.append(node)
        node_ports.append('<br>'.join([f'Port {p}' for p in G.nodes[node]['ports']]))
    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        text=node_ports,
        hovertemplate='%{text}',
        mode='markers',
        marker=dict(
            size=40,
            color='blue'
        )
    )

    # define layout
    layout = go.Layout(
        title='Network Topology',
        showlegend=False,
        hovermode='closest',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        margin=dict(b=20, l=5, r=5, t=40)
    )

    # create figure and plot
    fig = go.Figure(data=[edge_trace, node_trace], layout=layout)
    fig.show()


plot_topology(r'/scans/scan_20230330-104442.json')
