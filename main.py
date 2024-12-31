import tkinter as tk

from gui import App


def main():
    root = tk.Tk()
    app = App(root)
    app.run()


if __name__ == "__main__":
    main()
