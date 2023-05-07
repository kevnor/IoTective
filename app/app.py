from textual.app import App
from .dashboard import Dashboard
from .reports import Reports
from .scanning import Scanning


class IoTective(App):
    CSS_PATH = "app.css"
    TITLE = "IoTective"
    SUB_TITLE = "Automated Penetration Testing Tool for Home Networks"
    SCREENS = {"dashboard": Dashboard(), "scanning": Scanning(), "reports": Reports()}

    def on_mount(self) -> None:
        self.push_screen(Dashboard())


if __name__ == "__main__":
    app = IoTective()
    app.run()
