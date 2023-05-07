from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Button, Label, Header


class Dashboard(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Label("What do you want to do?", id="question")
        yield Button("Scanning", id="scanning", variant="primary")
        yield Button("View Reports", id="reports", variant="warning")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "scanning":
            self.app.push_screen("scanning")
