import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.constants import *

import clientf.tk_frames.search_page_support as search_page_support


class win_search:

    def __init__(self, frame, func_dict, pst_val, act_val, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = '#d9d9d9' # X11 color: 'gray85'
        _ana1color = '#d9d9d9' # X11 color: 'gray85'
        _ana2color = '#ececec' # Closest X11 color: 'gray92'

        self.top = top
        defx = int(1160 * 1.4 // 2)
        defy = int(720 * 1.8 // 2)
        top.iconbitmap(r'pics/icon.ico')

        self.Frame1 = tk.Frame(self.top)
        self.Frame1.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.Frame1.configure(relief='groove')
        self.Frame1.configure(borderwidth="2")
        self.Frame1.configure(relief="groove")
        self.Frame1.configure(background="#d9d9d9")
        self.Frame1.configure(highlightbackground="#d9d9d9")
        self.Frame1.configure(highlightcolor="black")

        self.Label1 = tk.Label(self.Frame1)
        self.Label1.place(relx=0.0, rely=0.0, height=57, width=1160)
        self.Label1.configure(activebackground="#f9f9f9")
        self.Label1.configure(activeforeground="black")
        self.Label1.configure(background="#eaddda")
        self.Label1.configure(compound='left')
        self.Label1.configure(disabledforeground="#a3a3a3")
        self.Label1.configure(foreground="#000000")
        self.Label1.configure(highlightbackground="#d9d9d9")
        self.Label1.configure(highlightcolor="black")
        self.Label1.configure(text='''Search Reservations''')

        self.home_btn = tk.Button(self.Frame1)
        self.home_btn.place(relx=0.862, rely=0.0, height=56, width=167)
        self.home_btn.configure(activebackground="#ececec")
        self.home_btn.configure(activeforeground="#000000")
        self.home_btn.configure(background="#de549a")
        self.home_btn.configure(compound='left')
        self.home_btn.configure(disabledforeground="#a3a3a3")
        self.home_btn.configure(foreground="#000000")
        self.home_btn.configure(highlightbackground="#d9d9d9")
        self.home_btn.configure(highlightcolor="black")
        self.home_btn.configure(pady="0")
        self.home_btn.configure(relief="flat")
        self.home_btn.configure(text='''Back''')
        self.home_btn.configure(command=lambda: (
        self.top.geometry("%dx%d" % (1160, 760)), self.top.resizable(1, 1), self.Frame1.destroy()))

        self.main_btn = tk.Button(self.Frame1)
        self.main_btn.place(relx=0.723, rely=0.0, height=56, width=167)
        self.main_btn.configure(activebackground="#ececec")
        self.main_btn.configure(activeforeground="#000000")
        self.main_btn.configure(background="#de549a")
        self.main_btn.configure(compound='left')
        self.main_btn.configure(disabledforeground="#a3a3a3")
        self.main_btn.configure(foreground="#000000")
        self.main_btn.configure(highlightbackground="#d9d9d9")
        self.main_btn.configure(highlightcolor="black")
        self.main_btn.configure(pady="0")
        self.main_btn.configure(text='''Main screen''')
        self.main_btn.configure(command=lambda: (self.Frame1.destroy(), self.top.geometry("%dx%d+523+254" % (1160, 760))))

        self.Frame2 = tk.Frame(self.Frame1)
        self.Frame2.place(relx=0.0, rely=0.075, relheight=0.086, relwidth=1.0)
        self.Frame2.configure(relief='groove')
        self.Frame2.configure(borderwidth="2")
        self.Frame2.configure(relief="groove")
        self.Frame2.configure(background="#f0ece9")
        self.Frame2.configure(highlightbackground="#d9d9d9")
        self.Frame2.configure(highlightcolor="black")

        self.Label2 = tk.Label(self.Frame2)
        self.Label2.place(relx=0.017, rely=0.154, height=41, width=224)
        self.Label2.configure(activebackground="#f9f9f9")
        self.Label2.configure(activeforeground="black")
        self.Label2.configure(anchor='w')
        self.Label2.configure(background="#f8d5c1")
        self.Label2.configure(compound='left')
        self.Label2.configure(disabledforeground="#a3a3a3")
        self.Label2.configure(foreground="#000000")
        self.Label2.configure(highlightbackground="#d9d9d9")
        self.Label2.configure(highlightcolor="black")
        self.Label2.configure(text='''User ID:''')

        self.active_resv = tk.Checkbutton(self.Frame2)
        self.active_resv.place(relx=0.629, rely=0.154, relheight=0.692
                , relwidth=0.157)
        self.active_resv.configure(activebackground="#ececec")
        self.active_resv.configure(activeforeground="#000000")
        self.active_resv.configure(anchor='w')
        self.active_resv.configure(background="#f8d5c1")
        self.active_resv.configure(compound='left')
        self.active_resv.configure(disabledforeground="#a3a3a3")
        self.active_resv.configure(foreground="#000000")
        self.active_resv.configure(highlightbackground="#d9d9d9")
        self.active_resv.configure(highlightcolor="black")
        self.active_resv.configure(justify='left')
        self.active_resv.configure(text='''Active reservations''')

        self.past_resv = tk.Checkbutton(self.Frame2)
        self.past_resv.place(relx=0.81, rely=0.154, relheight=0.692
                , relwidth=0.165)
        self.past_resv.configure(activebackground="#ececec")
        self.past_resv.configure(activeforeground="#000000")
        self.past_resv.configure(anchor='w')
        self.past_resv.configure(background="#f8d5c1")
        self.past_resv.configure(compound='left')
        self.past_resv.configure(disabledforeground="#a3a3a3")
        self.past_resv.configure(foreground="#000000")
        self.past_resv.configure(highlightbackground="#d9d9d9")
        self.past_resv.configure(highlightcolor="black")
        self.past_resv.configure(justify='left')
        self.past_resv.configure(text='''Past reservations''')



        self.id_entry = tk.Entry(self.Frame2)
        self.id_entry.place(relx=0.233, rely=0.154, height=41, relwidth=0.184)
        self.id_entry.configure(background="white")
        self.id_entry.configure(disabledforeground="#a3a3a3")
        self.id_entry.configure(font="TkFixedFont")
        self.id_entry.configure(foreground="#000000")
        self.id_entry.configure(highlightbackground="#d9d9d9")
        self.id_entry.configure(highlightcolor="black")
        self.id_entry.configure(insertbackground="black")
        self.id_entry.configure(selectbackground="blue")

        self.result_lstbx = ScrolledListBox(self.Frame1)
        self.result_lstbx.place(relx=0.0, rely=0.145, relheight=0.837
                , relwidth=1.0)
        self.result_lstbx.configure(background="white")
        self.result_lstbx.configure(cursor="xterm")
        self.result_lstbx.configure(disabledforeground="#a3a3a3")
        self.result_lstbx.configure(font="TkFixedFont")
        self.result_lstbx.configure(foreground="black")
        self.result_lstbx.configure(highlightbackground="#d9d9d9")
        self.result_lstbx.configure(highlightcolor="#d9d9d9")
        self.result_lstbx.configure(selectbackground="blue")
        self.result_lstbx.configure(selectforeground="white")

        # when the entry chances the search is performed
        self.id_entry.bind("<KeyRelease>", lambda x: (act_val.set(not act_val.get()), search_page_support.on_change(self.id_entry,
                                                                                               pst_val,
                                                                                               act_val, func_dict,
                                                                                               self.result_lstbx)))

        self.active_resv.bind('<Button-1>', lambda x: (act_val.set(not act_val.get()), search_page_support.on_change(self.id_entry,
                                                                                               pst_val,
                                                                                               act_val, func_dict,
                                                                                               self.result_lstbx)))

        self.past_resv.bind('<Button-1>', lambda x: (pst_val.set(not pst_val.get()), search_page_support.on_change(self.id_entry,
                                                                                               pst_val,
                                                                                               act_val, func_dict,
                                                                                               self.result_lstbx)))
        self.result_lstbx.insert(tk.END, "No results found")


# The following code is added to facilitate the Scrolled widgets you specified.
class AutoScroll(object):
    '''Configure the scrollbars for a widget.'''
    def __init__(self, master):
        #  Rozen. Added the try-except clauses so that this class
        #  could be used for scrolled entry widget for which vertical
        #  scrolling is not supported. 5/7/14.
        try:
            vsb = ttk.Scrollbar(master, orient='vertical', command=self.yview)
        except:
            pass
        hsb = ttk.Scrollbar(master, orient='horizontal', command=self.xview)
        try:
            self.configure(yscrollcommand=self._autoscroll(vsb))
        except:
            pass
        self.configure(xscrollcommand=self._autoscroll(hsb))
        self.grid(column=0, row=0, sticky='nsew')
        try:
            vsb.grid(column=1, row=0, sticky='ns')
        except:
            pass
        hsb.grid(column=0, row=1, sticky='ew')
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)
        # Copy geometry methods of master  (taken from ScrolledText.py)
        methods = tk.Pack.__dict__.keys() | tk.Grid.__dict__.keys() \
                  | tk.Place.__dict__.keys()
        for meth in methods:
            if meth[0] != '_' and meth not in ('config', 'configure'):
                setattr(self, meth, getattr(master, meth))

    @staticmethod
    def _autoscroll(sbar):
        '''Hide and show scrollbar as needed.'''
        def wrapped(first, last):
            first, last = float(first), float(last)
            if first <= 0 and last >= 1:
                sbar.grid_remove()
            else:
                sbar.grid()
            sbar.set(first, last)
        return wrapped

    def __str__(self):
        return str(self.master)

def _create_container(func):
    '''Creates a ttk Frame with a given master, and use this new frame to
    place the scrollbars and the widget.'''
    def wrapped(cls, master, **kw):
        container = ttk.Frame(master)
        container.bind('<Enter>', lambda e: _bound_to_mousewheel(e, container))
        container.bind('<Leave>', lambda e: _unbound_to_mousewheel(e, container))
        return func(cls, container, **kw)
    return wrapped

class ScrolledListBox(AutoScroll, tk.Listbox):
    '''A standard Tkinter Listbox widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        tk.Listbox.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)
    def size_(self):
        sz = tk.Listbox.size(self)
        return sz

import platform
def _bound_to_mousewheel(event, widget):
    child = widget.winfo_children()[0]
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        child.bind_all('<MouseWheel>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-MouseWheel>', lambda e: _on_shiftmouse(e, child))
    else:
        child.bind_all('<Button-4>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Button-5>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-Button-4>', lambda e: _on_shiftmouse(e, child))
        child.bind_all('<Shift-Button-5>', lambda e: _on_shiftmouse(e, child))

def _unbound_to_mousewheel(event, widget):
    if platform.system() == 'Windows' or platform.system() == 'Darwin':
        widget.unbind_all('<MouseWheel>')
        widget.unbind_all('<Shift-MouseWheel>')
    else:
        widget.unbind_all('<Button-4>')
        widget.unbind_all('<Button-5>')
        widget.unbind_all('<Shift-Button-4>')
        widget.unbind_all('<Shift-Button-5>')

def _on_mousewheel(event, widget):
    if platform.system() == 'Windows':
        widget.yview_scroll(-1*int(event.delta/120),'units')
    elif platform.system() == 'Darwin':
        widget.yview_scroll(-1*int(event.delta),'units')
    else:
        if event.num == 4:
            widget.yview_scroll(-1, 'units')
        elif event.num == 5:
            widget.yview_scroll(1, 'units')

def _on_shiftmouse(event, widget):
    if platform.system() == 'Windows':
        widget.xview_scroll(-1*int(event.delta/120), 'units')
    elif platform.system() == 'Darwin':
        widget.xview_scroll(-1*int(event.delta), 'units')
    else:
        if event.num == 4:
            widget.xview_scroll(-1, 'units')
        elif event.num == 5:
            widget.xview_scroll(1, 'units')


def start_up(frame, func_dict, top):
    search_page_support.main(frame, func_dict, top)




