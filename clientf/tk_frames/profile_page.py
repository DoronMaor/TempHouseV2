import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.constants import *

import clientf.tk_frames.profile_page_support as prof_page_support

class profile_page:
    def __init__(self,frame, logged_user, func_dict, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        _bgcolor = '#d9d9d9'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = '#d9d9d9' # X11 color: 'gray85'
        _ana1color = '#d9d9d9' # X11 color: 'gray85'
        _ana2color = '#ececec' # Closest X11 color: 'gray92'
        title_font = ("Verdana", 16, 'bold')
        def_font = ("Verdana", 12,)
        but_font = ("Arial Black", 11)

        defx = int(1160*1.4 // 2)
        defy = int(720*1.8 // 2)
        top.geometry("%dx%d+523+254" % (defx, defy))
        top.minsize(defx, defy)
        top.maxsize(1160, 760)
        top.resizable(1,  1)
        top.title("TempHouse - Profile")
        top.configure(background="#d9d9d9")
        top.iconbitmap(r'pics/icon.ico')
        self.top = top

        self.Frame1 = tk.Frame(self.top)
        self.Frame1.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.Frame1.configure(relief='groove')
        self.Frame1.configure(borderwidth="2")
        self.Frame1.configure(relief="groove")
        self.Frame1.configure(background="#f0ece9")

        self.Label1 = tk.Label(self.Frame1)
        self.Label1.place(relx=0.0, rely=0.0, height=41, relwidth=1.0)
        self.Label1.configure(anchor='center')
        self.Label1.configure(background="#eaddda")
        self.Label1.configure(compound='left')
        self.Label1.configure(disabledforeground="#a3a3a3")
        self.Label1.configure(foreground="#000000")
        self.Label1.configure(font=title_font)
        self.Label1.configure(text='''Profile Page''')

        self.profile_lstbx = tk.Listbox(self.Frame1)
        self.profile_lstbx.place(relx=0.013, rely=0.167, relheight=0.35
                , relwidth=0.32)
        self.profile_lstbx.configure(background="white")
        self.profile_lstbx.configure(disabledforeground="#a3a3a3")
        self.profile_lstbx.configure(font=def_font)
        self.profile_lstbx.configure(foreground="#000000")


        self.home_but = tk.Button(self.Frame1)
        self.home_but.place(relx=0.825, rely=0.0, height=44, width=147)
        self.home_but.configure(activebackground="#ececec")
        self.home_but.configure(activeforeground="#000000")
        self.home_but.configure(background="#de549a")
        self.home_but.configure(compound='left')
        self.home_but.configure(disabledforeground="#a3a3a3")
        self.home_but.configure(foreground="#000000")
        self.home_but.configure(highlightbackground="#d9d9d9")
        self.home_but.configure(highlightcolor="black")
        self.home_but.configure(pady="0")
        self.home_but.configure(font=but_font)
        self.home_but.configure(text='''Home''')

        self.home_but.configure(command=lambda: self.top.destroy())

        self.Label2 = tk.Label(self.Frame1)
        self.Label2.place(relx=0.35, rely=0.083, height=39, width=505)
        self.Label2.configure(anchor='center')
        self.Label2.configure(background="#f8d5c1")
        self.Label2.configure(compound='left')
        self.Label2.configure(disabledforeground="#a3a3a3")
        self.Label2.configure(foreground="#000000")
        self.Label2.configure(font=def_font)
        self.Label2.configure(text='''Active reservations (double-click to cancel)''')

        self.act_resvs_lstbx = ScrolledListBox(self.Frame1)
        self.act_resvs_lstbx.place(relx=0.35, rely=0.167, relheight=0.35
                , relwidth=0.626)
        self.act_resvs_lstbx.configure(background="white")
        self.act_resvs_lstbx.configure(cursor="xterm")
        self.act_resvs_lstbx.configure(disabledforeground="#a3a3a3")
        self.act_resvs_lstbx.configure(font="TkFixedFont")
        self.act_resvs_lstbx.configure(foreground="black")
        self.act_resvs_lstbx.configure(highlightbackground="#d9d9d9")
        self.act_resvs_lstbx.configure(highlightcolor="#d9d9d9")
        self.act_resvs_lstbx.configure(selectbackground="#f9f9f9")
        self.act_resvs_lstbx.configure(font=def_font)
        self.act_resvs_lstbx.configure(selectforeground="black")
        # bind double click to cancel reservation
        self.act_resvs_lstbx.bind('<Double-Button-1>', lambda x: func_dict.get('cancel_reservation')
            (logged_user.id, self.act_resvs_lstbx.get(tk.ACTIVE), self.Frame1, self.top))


        self.acc_lbl = tk.Label(self.Frame1)
        self.acc_lbl.place(relx=0.013, rely=0.083, height=39, width=257)
        self.acc_lbl.configure(activebackground="#f9f9f9")
        self.acc_lbl.configure(activeforeground="black")
        self.acc_lbl.configure(anchor='center')
        self.acc_lbl.configure(background="#f8d5c1")
        self.acc_lbl.configure(compound='left')
        self.acc_lbl.configure(disabledforeground="#a3a3a3")
        self.acc_lbl.configure(foreground="#000000")
        self.acc_lbl.configure(highlightbackground="#d9d9d9")
        self.acc_lbl.configure(highlightcolor="black")
        self.acc_lbl.configure(font=def_font)
        self.acc_lbl.configure(text='''Account Details''')

        self.past_lbl = tk.Label(self.Frame1)
        self.past_lbl.place(relx=0.35, rely=0.533, height=49, width=505)
        self.past_lbl.configure(activebackground="#f9f9f9")
        self.past_lbl.configure(activeforeground="black")
        self.past_lbl.configure(anchor='center')
        self.past_lbl.configure(background="#f8d5c1")
        self.past_lbl.configure(compound='left')
        self.past_lbl.configure(disabledforeground="#a3a3a3")
        self.past_lbl.configure(foreground="#000000")
        self.past_lbl.configure(highlightbackground="#d9d9d9")
        self.past_lbl.configure(highlightcolor="black")
        self.past_lbl.configure(font=def_font)
        self.past_lbl.configure(text='''Past reservations (double-click to rate)''')

        self.past_resvs_lstbx = ScrolledListBox(self.Frame1)
        self.past_resvs_lstbx.place(relx=0.35, rely=0.633, relheight=0.317
                , relwidth=0.626)
        self.past_resvs_lstbx.configure(background="white")
        self.past_resvs_lstbx.configure(cursor="xterm")
        self.past_resvs_lstbx.configure(disabledforeground="#a3a3a3")
        self.past_resvs_lstbx.configure(font="TkFixedFont")
        self.past_resvs_lstbx.configure(foreground="black")
        self.past_resvs_lstbx.configure(highlightbackground="#d9d9d9")
        self.past_resvs_lstbx.configure(highlightcolor="#d9d9d9")
        self.past_resvs_lstbx.configure(selectbackground="#f9f9f9")
        self.past_resvs_lstbx.configure(selectforeground="black")


        self.fun_lbl = tk.Label(self.Frame1)
        self.fun_lbl.place(relx=0.013, rely=0.533, height=47, width=257)
        self.fun_lbl.configure(activebackground="#f9f9f9")
        self.fun_lbl.configure(activeforeground="black")
        self.fun_lbl.configure(anchor='center')
        self.fun_lbl.configure(background="#f8d5c1")
        self.fun_lbl.configure(compound='left')
        self.fun_lbl.configure(disabledforeground="#a3a3a3")
        self.fun_lbl.configure(foreground="#000000")
        self.fun_lbl.configure(highlightbackground="#d9d9d9")
        self.fun_lbl.configure(highlightcolor="black")
        self.fun_lbl.configure(font=def_font)
        self.fun_lbl.configure(text='''Account Functions''')

        self.admin_btn = tk.Button(self.Frame1)
        self.admin_btn.place(relx=0.018, rely=0.65, height=64, relwidth=0.32)
        self.admin_btn.configure(activebackground="#ececec")
        self.admin_btn.configure(activeforeground="#000000")
        self.admin_btn.configure(background="#de549a")
        self.admin_btn.configure(compound='left')
        self.admin_btn.configure(disabledforeground="#a3a3a3")
        self.admin_btn.configure(foreground="#000000")
        self.admin_btn.configure(highlightbackground="#d9d9d9")
        self.admin_btn.configure(highlightcolor="black")
        self.admin_btn.configure(font=but_font)
        self.admin_btn.configure(pady="0")
        self.admin_btn.configure(command= lambda: func_dict['admin_window'](frame, top, "None"*100))

        if logged_user.is_admin:
            self.admin_btn.configure(text='''Admin Page''')
            self.admin_btn.configure(state="normal")
        else:
            self.admin_btn.configure(text='''Admin Page - Not an Admin''')
            self.admin_btn.configure(state="disabled")



        self.upload_btn = tk.Button(self.Frame1)
        self.upload_btn.place(relx=0.018, rely=0.8, height=64, relwidth=0.32)
        self.upload_btn.configure(activebackground="#ececec")
        self.upload_btn.configure(activeforeground="#000000")
        self.upload_btn.configure(background="#de549a")
        self.upload_btn.configure(compound='left')
        self.upload_btn.configure(cursor="fleur")
        self.upload_btn.configure(disabledforeground="#a3a3a3")
        self.upload_btn.configure(foreground="#000000")
        self.upload_btn.configure(highlightbackground="#d9d9d9")
        self.upload_btn.configure(highlightcolor="black")
        self.upload_btn.configure(pady="0")
        self.upload_btn.configure(font=but_font)
        self.upload_btn.configure(text='''Upload your apartment''')
        self.upload_btn.configure(command=lambda: func_dict['upload_apartment_window'](self.Frame1, self.top))


        # bind double click to rate
        self.past_resvs_lstbx.bind('<Double-Button-1>', lambda x: func_dict.get('rate_apartment_window')
            (self.past_resvs_lstbx.get(tk.ACTIVE), self.Frame1, self.top, self.past_resvs_lstbx.get(tk.ACTIVE)))

        prof_page_support.fill_listbox_user\
            (self.profile_lstbx, logged_user, self.act_resvs_lstbx, self.past_resvs_lstbx, self.Frame1, self.top)





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

def start_up(frame, logged_user, func_dict, mes):
    prof_page_support.main(frame, logged_user, func_dict, mes)

if __name__ == '__main__':
    prof_page_support.main()




