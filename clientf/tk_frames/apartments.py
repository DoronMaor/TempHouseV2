#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# GUI module generated by PAGE version 7.3
#  in conjunction with Tcl version 8.6
#    Apr 29, 2022 12:24:26 PM +0300  platform: Windows NT
import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.constants import *

import clientf.tk_frames.apartments_support as apartments_support

class Toplevel1:
    def __init__(self, frame, logged_user, func_dict, houses, area, top=None):
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
        fake_text = "8723y47 8 4 14 b 3215 d32 5 6 32 5 d2 5 23 dsf 623 sg dsfd 6532 23 432 4 21 rgwreg reg aef aerg erag re2dg "

        #top.geometry("1000x600+408+320")
        #top.resizable(0,  0)
        #top.title("TempHouse - Results")
        #top.configure(background="#d9d9d9")

        self.top = top

        self.Frame1 = tk.Frame(self.top)
        self.Frame1.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.Frame1.configure(relief='groove')
        self.Frame1.configure(borderwidth="2")
        self.Frame1.configure(relief="groove")
        self.Frame1.configure(background="#d9d9d9")

        self.results_lst_box = tk.Listbox(self.Frame1)
        self.results_lst_box.place(relx=-0.002, rely=0.067, relheight=0.937
                , relwidth=0.3)
        self.results_lst_box.configure(background="#e9e9e9")
        self.results_lst_box.configure(disabledforeground="#a3a3a3")
        self.results_lst_box.configure(font=def_font)
        self.results_lst_box.configure(foreground="#000000")

        # run function to fill the listbox
        apartments_support.fill_listbox(self.results_lst_box, houses)

        self.Frame2 = tk.Frame(self.Frame1)
        self.Frame2.place(relx=0.297, rely=0.067, relheight=0.942
                , relwidth=0.705)
        self.Frame2.configure(relief='groove')
        self.Frame2.configure(borderwidth="2")
        self.Frame2.configure(relief="groove")
        self.Frame2.configure(background="#f0ece9")

        self.ap_name = tk.Label(self.Frame2)
        self.ap_name.place(relx=0.014, rely=0.025, height=54, width=785)
        self.ap_name.configure(anchor='center')
        self.ap_name.configure(background="#f8d5c1")
        self.ap_name.configure(compound='center')
        self.ap_name.configure(disabledforeground="#a3a3a3")
        self.ap_name.configure(foreground="#000000")
        self.ap_name.configure(font=def_font)
        self.ap_name.configure(text='''name''')

        self.pic_frame = tk.Frame(self.Frame2)
        self.pic_frame.place(relx=0.52, rely=0.142, relheight=0.404
                , relwidth=0.461)
        self.pic_frame.configure(relief='groove')
        self.pic_frame.configure(borderwidth="2")
        self.pic_frame.configure(relief="groove")
        self.pic_frame.configure(background="#d9d9d9")

        # canvas on top of the pic_frame
        self.canvas = tk.Canvas(self.pic_frame)
        self.canvas.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.canvas.configure(background="#d9d9d9")
        self.canvas.configure(borderwidth="2")
        self.canvas.configure(insertbackground="black")
        self.canvas.configure(relief='groove')

        # image on top of the canvas
        self.im = tk.PhotoImage(master=self.canvas, format='png')
        self.canvas.create_image(0, 0, image=self.im, anchor='nw')

        self.ap_rooms_beds_price = tk.Label(self.Frame2, wraplength=375, justify='left')
        self.ap_rooms_beds_price.place(relx=0.014, rely=0.142, height=284,width=400)
        self.ap_rooms_beds_price.configure(anchor='nw')
        self.ap_rooms_beds_price.configure(background="#f3f3f3")
        self.ap_rooms_beds_price.configure(compound='left')
        self.ap_rooms_beds_price.configure(disabledforeground="#a3a3a3")
        self.ap_rooms_beds_price.configure(foreground="#000000")
        self.ap_rooms_beds_price.configure(font=def_font)
        self.ap_rooms_beds_price.configure(text=fake_text)

        self.desc_lbl = tk.Label(self.Frame2, wraplength=660, justify='left')
        self.desc_lbl.place(relx=0.014, rely=0.584, height=198, width=680)
        self.desc_lbl.configure(activebackground="#f9f9f9")
        self.desc_lbl.configure(activeforeground="black")
        self.desc_lbl.configure(anchor='nw')
        self.desc_lbl.configure(background="#eaddda")
        self.desc_lbl.configure(compound='left')
        self.desc_lbl.configure(disabledforeground="#a3a3a3")
        self.desc_lbl.configure(foreground="#000000")
        self.desc_lbl.configure(highlightbackground="#d9d9d9")
        self.desc_lbl.configure(highlightcolor="black")
        self.desc_lbl.configure(font=def_font)
        self.desc_lbl.configure(text=fake_text)

        self.reviews_but = tk.Button(self.Frame2)
        self.reviews_but.place(relx=0.871, rely=0.584, height=198, width=77)
        self.reviews_but.configure(activebackground="#ececec")
        self.reviews_but.configure(activeforeground="#000000")
        self.reviews_but.configure(background="#f8d5c1")
        self.reviews_but.configure(compound='left')
        self.reviews_but.configure(disabledforeground="#a3a3a3")
        self.reviews_but.configure(foreground="#000000")
        self.reviews_but.configure(highlightbackground="#d9d9d9")
        self.reviews_but.configure(highlightcolor="black")
        self.reviews_but.configure(pady="0")
        self.reviews_but.configure(font=but_font)
        self.reviews_but.configure(text='''reviews''')

        self.rent_button = tk.Button(self.Frame2)
        self.rent_button.place(relx=0.014, rely=0.903, height=56, width=774)
        self.rent_button.configure(activebackground="#ececec")
        self.rent_button.configure(activeforeground="#000000")
        self.rent_button.configure(background="#244244")
        self.rent_button.configure(compound='left')
        self.rent_button.configure(disabledforeground="#a3a3a3")
        self.rent_button.configure(foreground="#ffffff")
        self.rent_button.configure(highlightbackground="#d9d9d9")
        self.rent_button.configure(highlightcolor="black")
        self.rent_button.configure(pady="0")
        self.rent_button.configure(font=but_font)
        self.rent_button.configure(text='''rent it''')
        self.rent_button.configure(command=lambda y=1: func_dict.get("book_window")(top, self.Frame1, self.results_lst_box.get(ANCHOR) , houses))

        self.top_lbl = tk.Label(self.Frame1)
        self.top_lbl.place(relx=-0.06, rely=0.0, height=50, width=1400)
        self.top_lbl.configure(anchor='center')
        self.top_lbl.configure(background="#eaddda")
        self.top_lbl.configure(compound='left')
        self.top_lbl.configure(disabledforeground="#a3a3a3")
        self.top_lbl.configure(foreground="#000000")
        self.top_lbl.configure(font=title_font)
        self.top_lbl.configure(text='''Search Results''')

        self.Button3 = tk.Button(self.Frame1)
        self.Button3.place(relx=0.89, rely=0.0, height=52, width=129)
        self.Button3.configure(activebackground="#ececec")
        self.Button3.configure(activeforeground="#000000")
        self.Button3.configure(background="#de549a")
        self.Button3.configure(compound='left')
        self.Button3.configure(disabledforeground="#a3a3a3")
        self.Button3.configure(foreground="#000000")
        self.Button3.configure(highlightbackground="#d9d9d9")
        self.Button3.configure(highlightcolor="black")
        self.Button3.configure(pady="0")
        self.Button3.configure(font=but_font)
        self.Button3.configure(text='''Home''')
        # destory window
        self.Button3.configure(command=lambda: self.Frame1.destroy())



        self.sort_price = tk.Button(self.Frame1)
        self.sort_price.place(relx=0.014, rely=0.9, height=64, width=147)
        self.sort_price.configure(activebackground="#ececec")
        self.sort_price.configure(activeforeground="#000000")
        self.sort_price.configure(background="#d9d9d9")
        self.sort_price.configure(compound='left')
        self.sort_price.configure(disabledforeground="#a3a3a3")
        self.sort_price.configure(foreground="#000000")
        self.sort_price.configure(highlightbackground="#d9d9d9")
        self.sort_price.configure(highlightcolor="black")
        self.sort_price.configure(pady="0")
        self.sort_price.configure(font=but_font)
        self.sort_price.configure(text='''Sort by price''')
        self.sort_price.configure(command=lambda: apartments_support.sort_by_price(self.results_lst_box, houses))


        self.sort_location = tk.Button(self.Frame1)
        self.sort_location.place(relx=0.153, rely=0.9, height=64, width=147)
        self.sort_location.configure(activebackground="#ececec")
        self.sort_location.configure(activeforeground="#000000")
        self.sort_location.configure(background="#d9d9d9")
        self.sort_location.configure(compound='left')
        self.sort_location.configure(disabledforeground="#a3a3a3")
        self.sort_location.configure(foreground="#000000")
        self.sort_location.configure(highlightbackground="#d9d9d9")
        self.sort_location.configure(highlightcolor="black")
        self.sort_location.configure(pady="0")
        self.sort_location.configure(font=but_font)
        self.sort_location.configure(text='''Sort by location''')
        self.sort_location.configure(command=lambda: apartments_support.sort_by_location(self.results_lst_box, houses, area))


        self.des_or_rev_txt = ScrolledListBox(self.Frame2)
        self.des_or_rev_txt.place(relx=0.014, rely=0.584, relheight=0.299
                , relwidth=0.844)
        self.des_or_rev_txt.configure(background="white")
        self.des_or_rev_txt.configure(cursor="xterm")
        self.des_or_rev_txt.configure(disabledforeground="black")
        self.des_or_rev_txt.configure(font=def_font)
        self.des_or_rev_txt.configure(foreground="black")
        self.des_or_rev_txt.configure(highlightbackground="#d9d9d9")
        self.des_or_rev_txt.configure(highlightcolor="#d9d9d9")
        self.des_or_rev_txt.configure(selectbackground="blue")
        self.des_or_rev_txt.configure(selectforeground="white")

        self.reviews_but.configure(command=lambda: apartments_support.on_reviews_select(self.results_lst_box.get(ANCHOR), self.des_or_rev_txt, houses))

        self.results_lst_box.bind("<<ListboxSelect>>", lambda x: apartments_support.on_list_select(houses, self.results_lst_box.get(ANCHOR), self.ap_name, self.ap_rooms_beds_price,
                                                                                                   self.desc_lbl, (self.canvas, self.im), self.reviews_but, self.rent_button, self.des_or_rev_txt, self.top))
        self.canvas.config(image=None)
        self.reviews_but.config(state=DISABLED)
        self.rent_button.config(state=DISABLED)





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







def start_up(frame, logged_user, func_dict, houses, area, pics, win):
    apartments_support.main(frame, logged_user, func_dict, houses, area, pics, win)

"""
if __name__ == '__main__':
    apartments_support.main()
"""



