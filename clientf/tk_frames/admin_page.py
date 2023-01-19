#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# GUI module generated by PAGE version 7.3
#  in conjunction with Tcl version 8.6
#    May 05, 2022 03:47:44 PM +0300  platform: Windows NT

import tkinter as tk
import tkinter.ttk as ttk


import clientf.tk_frames.admin_page_support as admin_page_support
class win_admin:
    def __init__(self, frame, func_dict, logged_user, top=None):
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

        defx = int(1160 * 1.4 // 2)
        defy = int(720 * 1.8 // 2)
        top.geometry("1160x720")
        top.maxsize(1160, 760)
        top.resizable(0, 0)
        top.title("TempHouse - Admin")
        top.iconbitmap(r'pics/icon.ico')
        self.top = top


        self.Frame1 = tk.Frame(self.top)
        self.Frame1.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.Frame1.configure(relief='groove')
        self.Frame1.configure(borderwidth="2")
        self.Frame1.configure(relief="groove")
        self.Frame1.configure(background="#f0ece9")

        self.Label1 = tk.Label(self.Frame1)
        self.Label1.place(relx=-0.008, rely=-0.001, height=57, width=1160)
        self.Label1.configure(background="#eaddda")
        self.Label1.configure(compound='left')
        self.Label1.configure(disabledforeground="#a3a3a3")
        self.Label1.configure(foreground="#000000")
        self.Label1.configure(text='''Admin Page''')

        self.home_btn = tk.Button(self.Frame1)
        self.home_btn.place(relx=0.862, rely=0.0, height=56, width=167)
        self.home_btn.configure(activebackground="#de549a")
        self.home_btn.configure(activeforeground="#000000")
        self.home_btn.configure(background="#de549a")
        self.home_btn.configure(compound='left')
        self.home_btn.configure(disabledforeground="#a3a3a3")
        self.home_btn.configure(foreground="#000000")
        self.home_btn.configure(highlightbackground="#d9d9d9")
        self.home_btn.configure(highlightcolor="black")
        self.home_btn.configure(pady="0")
        self.home_btn.configure(relief="sunken")
        self.home_btn.configure(state='active')
        self.home_btn.configure(text='''Back''')
        self.home_btn.configure(command=lambda: (self.top.geometry("%dx%d" % (defx, defy)), self.top.resizable(1,  1) ,self.Frame1.destroy()))

        self.map_lunch = tk.Button(self.Frame1)
        self.map_lunch.place(relx=0.802, rely=0.092, height=114, width=217)
        self.map_lunch.configure(activebackground="#ececec")
        self.map_lunch.configure(activeforeground="#000000")
        self.map_lunch.configure(background="#244244")
        self.map_lunch.configure(compound='left')
        self.map_lunch.configure(cursor="fleur")
        self.map_lunch.configure(disabledforeground="#a3a3a3")
        self.map_lunch.configure(foreground="#ffffff")
        self.map_lunch.configure(highlightbackground="#d9d9d9")
        self.map_lunch.configure(highlightcolor="black")
        self.map_lunch.configure(pady="0")
        self.map_lunch.configure(text='''Map of Apartments''')
        self.map_lunch.configure(command=lambda: admin_page_support.apartments_map(func_dict))


        self.date_lbl = tk.Label(self.Frame1)
        self.date_lbl.place(relx=0.009, rely=0.092, height=61, width=903)
        self.date_lbl.configure(anchor='w')
        self.date_lbl.configure(background="#ebddda")
        self.date_lbl.configure(compound='left')
        self.date_lbl.configure(disabledforeground="#a3a3a3")
        self.date_lbl.configure(foreground="#000000")
        self.date_lbl.configure(text='''Current date [yyyy-mm-dd]:''')

        self.gen_apartments_btn = tk.Button(self.Frame1)
        self.gen_apartments_btn.place(relx=0.802, rely=0.263, height=124
                , width=217)
        self.gen_apartments_btn.configure(activebackground="#ececec")
        self.gen_apartments_btn.configure(activeforeground="#000000")
        self.gen_apartments_btn.configure(background="#244244")
        self.gen_apartments_btn.configure(compound='left')
        self.gen_apartments_btn.configure(disabledforeground="#a3a3a3")
        self.gen_apartments_btn.configure(foreground="#ffffff")
        self.gen_apartments_btn.configure(highlightbackground="#d9d9d9")
        self.gen_apartments_btn.configure(highlightcolor="black")
        self.gen_apartments_btn.configure(pady="0")
        self.gen_apartments_btn.configure(text='''Generate all apartments txt report''')
        self.gen_apartments_btn.configure(command=lambda: admin_page_support.generate_txt_apartments(func_dict, self.result_txt))

        self.gen_money_btn = tk.Button(self.Frame1)
        self.gen_money_btn.place(relx=0.802, rely=0.447, height=124, width=217)
        self.gen_money_btn.configure(activebackground="#ececec")
        self.gen_money_btn.configure(activeforeground="#000000")
        self.gen_money_btn.configure(background="#244244")
        self.gen_money_btn.configure(compound='left')
        self.gen_money_btn.configure(disabledforeground="#a3a3a3")
        self.gen_money_btn.configure(foreground="#ffffff")
        self.gen_money_btn.configure(highlightbackground="#d9d9d9")
        self.gen_money_btn.configure(highlightcolor="black")
        self.gen_money_btn.configure(pady="0")
        self.gen_money_btn.configure(text='''Generate money txt report''')
        self.gen_money_btn.configure(command=lambda: admin_page_support.generate_money_report(func_dict, self.result_txt))

        self.result_txt = ScrolledText(self.Frame1)
        self.result_txt.place(relx=0.009, rely=0.263, relheight=0.539
                , relwidth=0.774)
        self.result_txt.configure(background="white")
        self.result_txt.configure(font=def_font)
        self.result_txt.configure(foreground="black")
        self.result_txt.configure(highlightbackground="#d9d9d9")
        self.result_txt.configure(highlightcolor="black")
        self.result_txt.configure(insertbackground="black")
        self.result_txt.configure(insertborderwidth="3")
        self.result_txt.configure(selectbackground="blue")
        self.result_txt.configure(selectforeground="white")
        self.result_txt.configure(wrap="none")

        self.popular_dates_btn = tk.Button(self.Frame1)
        self.popular_dates_btn.place(relx=0.802, rely=0.632, height=124, width=217)
        self.popular_dates_btn.configure(activebackground="#ececec")
        self.popular_dates_btn.configure(activeforeground="#000000")
        self.popular_dates_btn.configure(background="#244244")
        self.popular_dates_btn.configure(compound='left')
        self.popular_dates_btn.configure(disabledforeground="#a3a3a3")
        self.popular_dates_btn.configure(foreground="#ffffff")
        self.popular_dates_btn.configure(highlightbackground="#d9d9d9")
        self.popular_dates_btn.configure(highlightcolor="black")
        self.popular_dates_btn.configure(pady="0")
        self.popular_dates_btn.configure(text='''Generate popular dates txt report''')
        self.popular_dates_btn.configure(command=lambda: admin_page_support.generate_txt_popular_dates(func_dict, self.result_txt))

        self.search_btn = tk.Button(self.Frame1)
        self.search_btn.place(relx=0.723, rely=0.0, height=56, width=167)
        self.search_btn.configure(activebackground="#ececec")
        self.search_btn.configure(activeforeground="#000000")
        self.search_btn.configure(background="#de549a")
        self.search_btn.configure(compound='left')
        self.search_btn.configure(disabledforeground="#a3a3a3")
        self.search_btn.configure(foreground="#000000")
        self.search_btn.configure(highlightbackground="#d9d9d9")
        self.search_btn.configure(highlightcolor="black")
        self.search_btn.configure(pady="0")
        self.search_btn.configure(text='''Reservations''')
        self.search_btn.configure(command= lambda :(func_dict['search_admin_window'](self.top,self.top)))

        self.date_lbl_1 = tk.Label(self.Frame1)
        self.date_lbl_1.place(relx=0.009, rely=0.197, height=41, width=243)
        self.date_lbl_1.configure(activebackground="#f9f9f9")
        self.date_lbl_1.configure(activeforeground="black")
        self.date_lbl_1.configure(anchor='w')
        self.date_lbl_1.configure(background="#f8d5c1")
        self.date_lbl_1.configure(compound='left')
        self.date_lbl_1.configure(disabledforeground="#a3a3a3")
        self.date_lbl_1.configure(foreground="#000000")
        self.date_lbl_1.configure(highlightbackground="#d9d9d9")
        self.date_lbl_1.configure(highlightcolor="black")
        self.date_lbl_1.configure(text='''Last generated report:''')

        self.att_lbl = tk.Label(self.Frame1)
        self.att_lbl.place(relx=0.009, rely=0.842, height=61, width=1133)
        self.att_lbl.configure(activebackground="#f9f9f9")
        self.att_lbl.configure(activeforeground="black")
        self.att_lbl.configure(anchor='w')
        self.att_lbl.configure(background="#ebddda")
        self.att_lbl.configure(compound='left')
        self.att_lbl.configure(disabledforeground="#a3a3a3")
        self.att_lbl.configure(foreground="#000000")
        self.att_lbl.configure(highlightbackground="#d9d9d9")
        self.att_lbl.configure(highlightcolor="black")
        self.att_lbl.configure(text='''Attractions file:''')

        self.date_entry = tk.Entry(self.Frame1)
        self.date_entry.place(relx=0.224, rely=0.105, height=41, relwidth=0.159)
        self.date_entry.configure(background="white")
        self.date_entry.configure(disabledforeground="#a3a3a3")
        self.date_entry.configure(font="TkFixedFont")
        self.date_entry.configure(foreground="#000000")
        self.date_entry.configure(insertbackground="black")
        # set text
        self.date_entry.insert(0, func_dict['get_date']().strftime('%Y-%m-%d'))

        self.att_entry = tk.Entry(self.Frame1)
        self.att_entry.place(relx=0.224, rely=0.855, height=41, relwidth=0.374)
        self.att_entry.configure(background="white")
        self.att_entry.configure(disabledforeground="#a3a3a3")
        self.att_entry.configure(font="TkFixedFont")
        self.att_entry.configure(foreground="#000000")
        self.att_entry.configure(highlightbackground="#d9d9d9")
        self.att_entry.configure(highlightcolor="black")
        self.att_entry.configure(insertbackground="black")
        self.att_entry.configure(selectbackground="blue")
        self.att_entry.configure(selectforeground="white")

        self.set_date_btn = tk.Button(self.Frame1)
        self.set_date_btn.place(relx=0.405, rely=0.105, height=41, width=117)
        self.set_date_btn.configure(activebackground="#ececec")
        self.set_date_btn.configure(activeforeground="#000000")
        self.set_date_btn.configure(background="#244244")
        self.set_date_btn.configure(compound='left')
        self.set_date_btn.configure(cursor="fleur")
        self.set_date_btn.configure(disabledforeground="#a3a3a3")
        self.set_date_btn.configure(foreground="#ffffff")
        self.set_date_btn.configure(highlightbackground="#d9d9d9")
        self.set_date_btn.configure(highlightcolor="black")
        self.set_date_btn.configure(pady="0")
        self.set_date_btn.configure(text='''Apply''')
        self.set_date_btn.configure(command= lambda: func_dict['set_date'](self.date_entry.get(), self.top))

        self.set_att_btn = tk.Button(self.Frame1)
        self.set_att_btn.place(relx=0.621, rely=0.855, height=41, width=117)
        self.set_att_btn.configure(activebackground="#ececec")
        self.set_att_btn.configure(activeforeground="#000000")
        self.set_att_btn.configure(background="#244244")
        self.set_att_btn.configure(compound='left')
        self.set_att_btn.configure(disabledforeground="#a3a3a3")
        self.set_att_btn.configure(foreground="#ffffff")
        self.set_att_btn.configure(highlightbackground="#d9d9d9")
        self.set_att_btn.configure(highlightcolor="black")
        self.set_att_btn.configure(pady="0")
        self.set_att_btn.configure(text='''Apply''')
        self.set_att_btn.configure(command= lambda : admin_page_support.set_attractions(func_dict, self.att_entry.get(), top))

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

class ScrolledText(AutoScroll, tk.Text):
    '''A standard Tkinter Text widget with scrollbars that will
    automatically show/hide as needed.'''
    @_create_container
    def __init__(self, master, **kw):
        tk.Text.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)

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
def start_up(frame, func_dict, logged_user, top):
    admin_page_support.main(frame, func_dict, logged_user, top)

if __name__ == '__main__':
    admin_page_support.main()




