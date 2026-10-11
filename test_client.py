"""Regression tests for standalone-client chat message interactions.

Run with ``python -m unittest test_client``.  The test uses Qt's offscreen
platform, so it does not need a visible desktop session.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtGui import QContextMenuEvent, QGuiApplication
from PyQt6.QtTest import QSignalSpy, QTest
from PyQt6.QtWidgets import QApplication, QLabel, QListWidget, QListWidgetItem, QPushButton

from client import (
    APP_VERSION,
    STYLE,
    ChatBubble,
    Login,
    Main,
    configure_message_list,
    make_identity,
)


class MainMessageHandler:
    def __init__(self):
        self.saved = []
        self.status = Mock()

    def statusBar(self):
        return self.status

    def copy_text(self, text):
        Main.copy_text(self, text)

    def save_as(self, row):
        self.saved.append(row)


class ChatBubbleInteractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setStyle("Fusion")
        cls.app.setStyleSheet(STYLE)

    def make_chat(
        self,
        body_text="A message that should stay inside its bubble",
        kind="text",
        direction="in",
    ):
        chat = QListWidget()
        chat.resize(600, 360)
        chat.setObjectName("chatMessages")
        configure_message_list(chat)

        row = {
            "direction": direction,
            "ts": time.time(),
            "body": body_text,
            "kind": kind,
            "status": "ok",
        }
        bubble = ChatBubble(row)
        item = QListWidgetItem()
        item.setSizeHint(bubble.sizeHint())
        chat.addItem(item)
        chat.setItemWidget(item, bubble)
        chat.show()
        self.app.processEvents()
        return chat, bubble, row

    def test_left_click_copies_message_action_without_selecting_row(self):
        chat, bubble, row = self.make_chat()
        try:
            body = next(
                label for label in bubble.findChildren(QLabel) if row["body"] in label.text()
            )
            self.assertTrue(
                body.textInteractionFlags() & Qt.TextInteractionFlag.TextSelectableByMouse
            )
            self.assertFalse(
                bubble.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            )

            handler = MainMessageHandler()
            bubble.left_clicked.connect(lambda clicked_row: Main.message_clicked(handler, clicked_row))
            QGuiApplication.clipboard().clear()
            left_click = QSignalSpy(bubble.left_clicked)
            context_menu = QSignalSpy(bubble.context_menu_requested)
            body_pos = body.rect().center()
            context_event = QContextMenuEvent(
                QContextMenuEvent.Reason.Mouse, body_pos, body.mapToGlobal(body_pos)
            )
            QApplication.sendEvent(body, context_event)
            self.assertEqual(len(context_menu), 1)
            self.assertEqual(context_menu[0][0]["body"], row["body"])

            QTest.mouseClick(body, Qt.MouseButton.LeftButton, pos=body.rect().center())
            self.app.processEvents()
            self.assertEqual(len(left_click), 1)
            self.assertEqual(left_click[0][0]["body"], row["body"])
            self.assertEqual(QGuiApplication.clipboard().text(), row["body"])
            self.assertEqual(chat.selectedIndexes(), [])

            # Clicking unused space on the same list row must not select the row either.
            row_rect = chat.visualItemRect(chat.item(0))
            empty_space = chat.viewport().rect().right() - 4
            QTest.mouseClick(
                chat.viewport(),
                Qt.MouseButton.LeftButton,
                pos=QPoint(empty_space, row_rect.center().y()),
            )
            self.app.processEvents()
            self.assertEqual(len(left_click), 1)
            self.assertEqual(chat.selectedIndexes(), [])
        finally:
            chat.close()

    def test_login_button_accepts_qt_clicked_bool_in_compiled_module(self):
        # Exercise the actual Qt signal, not just Login.accept() directly.
        # Cython callables must accept clicked(bool)'s extra argument.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("client.CFG", root / "config.json"), patch("client.IDDIR", root):
                make_identity("test-identity")
                dialog = Login()
                try:
                    dialog.show()
                    self.app.processEvents()
                    button = next(
                        button for button in dialog.findChildren(QPushButton)
                        if button.objectName() == "primary"
                    )
                    with patch.object(sys, "excepthook") as errors:
                        QTest.mouseClick(button, Qt.MouseButton.LeftButton)
                        self.app.processEvents()
                    errors.assert_not_called()
                    self.assertEqual(dialog.result(), 1)
                    self.assertTrue((root / "config.json").is_file())
                finally:
                    dialog.close()

    def test_left_click_on_file_bubble_emits_file_action(self):
        chat, bubble, row = self.make_chat("report.pdf", kind="file")
        try:
            body = next(label for label in bubble.findChildren(QLabel) if "report.pdf" in label.text())
            handler = MainMessageHandler()
            bubble.left_clicked.connect(lambda clicked_row: Main.message_clicked(handler, clicked_row))
            left_click = QSignalSpy(bubble.left_clicked)
            QTest.mouseClick(body, Qt.MouseButton.LeftButton, pos=body.rect().center())
            self.app.processEvents()
            self.assertEqual(len(left_click), 1)
            self.assertEqual(left_click[0][0]["kind"], "file")
            self.assertEqual(left_click[0][0]["body"], row["body"])
            self.assertEqual(handler.saved, [row])
        finally:
            chat.close()

    def test_left_click_on_outgoing_message_copies_to_clipboard(self):
        chat, bubble, row = self.make_chat("my message", direction="out")
        try:
            handler = MainMessageHandler()
            bubble.left_clicked.connect(lambda clicked_row: Main.message_clicked(handler, clicked_row))
            body = next(label for label in bubble.findChildren(QLabel) if row["body"] in label.text())
            QGuiApplication.clipboard().clear()
            QTest.mouseClick(body, Qt.MouseButton.LeftButton, pos=body.rect().center())
            self.app.processEvents()
            self.assertEqual(QGuiApplication.clipboard().text(), "my message")
            self.assertEqual(chat.selectedIndexes(), [])
        finally:
            chat.close()

    def test_drag_selecting_text_does_not_trigger_click_action(self):
        chat, bubble, row = self.make_chat(
            "Drag across this message to select text without copying the whole message"
        )
        try:
            body = next(label for label in bubble.findChildren(QLabel) if row["body"] in label.text())
            left_click = QSignalSpy(bubble.left_clicked)
            start = QPoint(5, body.height() // 2)
            end = QPoint(min(body.width() - 3, start.x() + 65), start.y())
            QTest.mousePress(body, Qt.MouseButton.LeftButton, pos=start)
            QTest.mouseMove(body, end, delay=20)
            QTest.mouseRelease(body, Qt.MouseButton.LeftButton, pos=end)
            self.app.processEvents()
            self.assertEqual(len(left_click), 0)
            self.assertTrue(body.selectedText())
            self.assertEqual(chat.selectedIndexes(), [])
        finally:
            chat.close()

    def test_version_and_short_bubble_sizing(self):
        self.assertEqual(APP_VERSION, "1.1")
        chat, bubble, _ = self.make_chat("hi")
        try:
            self.assertLess(bubble.bubble.width(), chat.viewport().width() // 4)
        finally:
            chat.close()

    def test_incoming_and_outgoing_bubbles_use_opposite_edges(self):
        chat = QListWidget()
        chat.resize(600, 360)
        chat.setObjectName("chatMessages")
        configure_message_list(chat)
        bubbles = []
        for direction in ("in", "out"):
            bubble = ChatBubble(
                {
                    "direction": direction,
                    "ts": time.time(),
                    "body": "short",
                    "kind": "text",
                    "status": "ok",
                }
            )
            item = QListWidgetItem()
            item.setSizeHint(bubble.sizeHint())
            chat.addItem(item)
            chat.setItemWidget(item, bubble)
            bubbles.append(bubble)
        chat.show()
        self.app.processEvents()
        try:
            incoming_x = bubbles[0].bubble.mapTo(chat.viewport(), QPoint(0, 0)).x()
            outgoing_right = bubbles[1].bubble.mapTo(chat.viewport(), QPoint(0, 0)).x() + bubbles[1].bubble.width()
            self.assertLessEqual(incoming_x, 2)
            self.assertGreaterEqual(outgoing_right, chat.viewport().width() - 2)
            self.assertLess(bubbles[0].bubble.width(), 120)
            self.assertLess(bubbles[1].bubble.width(), 120)
        finally:
            chat.close()

    def test_click_handler_copies_text_and_routes_files_to_save_as(self):
        handler = MainMessageHandler()
        text_row = {"kind": "text", "body": "copied on click"}
        file_row = {"kind": "file", "body": "report.pdf"}
        Main.message_clicked(handler, text_row)
        Main.message_clicked(handler, file_row)
        self.assertEqual(QGuiApplication.clipboard().text(), "copied on click")
        self.assertEqual(handler.saved, [file_row])

    def test_saving_local_large_file_is_delegated_to_worker_job(self):
        class SaveHarness:
            def run_job(self, key, function):
                self.job = (key, function)

        class Progress:
            def __init__(self):
                self.values = []

            def emit(self, value):
                self.values.append(value)

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            destination = Path(directory) / "saved.bin"
            payload = os.urandom(2 * 1024 * 1024 + 37)
            source.write_bytes(payload)
            row = {"body": "source.bin", "local_path": str(source), "kind": "file"}
            harness = SaveHarness()
            with patch(
                "client.QFileDialog.getSaveFileName",
                return_value=(str(destination), ""),
            ):
                Main.save_as(harness, row)

            key, job = harness.job
            self.assertTrue(key.startswith("save:"))
            progress = Progress()
            with ThreadPoolExecutor(max_workers=1) as executor:
                result = executor.submit(job, progress).result(timeout=10)
            self.assertEqual(Path(result), destination)
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(progress.values[-1], 100)
            self.assertEqual(list(Path(directory).glob(".*.part")), [])


if __name__ == "__main__":
    unittest.main()
