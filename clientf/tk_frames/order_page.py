import _thread
import threading
import tkinter as tk
from tkinter.constants import *
from tkHelper import *

import clientf.tk_frames.order_support as order_support

class renting_page:
    def __init__(self,s_apartment, search_details, days, func_dict, logged, client_socket, top=None):
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

        top.geometry("809x450+504+297")
        top.minsize(120, 1)
        top.maxsize(3604, 1061)
        top.resizable(0, 0)
        top.title("TempHouse - Rent")
        top.configure(background="#d9d9d9")
        top.iconbitmap(r'pics/icon.ico')
        self.top = top

        # basic frame for the whole page
        self.frame_basic = tk.Frame(top)
        self.frame_basic.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        if logged:
            txt = Label(self.frame_basic, text="You have been afk for too long. Your reservation for %s has been canceled. "
                            "\n In the meantime, please rate the apartments you have visited them in the past." % s_apartment.name, font=def_font, bg=bg_color, fg=txt_color)
            txt.pack(fill="both", expand="YES")
            btn = Button(self.frame_basic, text="Profile Page", command=lambda: (self.top.destroy(), func_dict["profile_window"](),), font=def_font)
            btn.pack(side=LEFT, expand="YES", fill="both")
        else:
            txt = Label(self.frame_basic, text="You have been afk for too long. Your reservation for %s has been canceled." % s_apartment.name, font=def_font, bg=bg_color, fg=txt_color)
            txt.pack(fill="both", expand="YES")
            btn = Button(self.frame_basic, text="OK", command=lambda: self.top.destroy(), font=def_font)
            btn.pack(side=LEFT, expand="YES", fill="both")

        self.Frame1 = tk.Frame(self.frame_basic)
        self.Frame1.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.Frame1.configure(relief='groove')
        self.Frame1.configure(borderwidth="2")
        self.Frame1.configure(relief="groove")
        self.Frame1.configure(background="#f0ece9")

        self.top_lbl = tk.Label(self.Frame1)
        self.top_lbl.place(relx=0.0, rely=0.0, height=53, relwidth=1.0)
        self.top_lbl.configure(anchor='w')
        self.top_lbl.configure(background="#eaddda")
        self.top_lbl.configure(compound='left')
        self.top_lbl.configure(disabledforeground="#a3a3a3")
        self.top_lbl.configure(foreground="#000000")
        self.top_lbl.configure(font=title_font)
        self.top_lbl.configure(text='''Order a TempHouse''')

        self.summary_frame = tk.Frame(self.Frame1)
        self.summary_frame.place(relx=0.507, rely=0.111, relheight=0.673
                , relwidth=0.481)
        self.summary_frame.configure(relief='groove')
        self.summary_frame.configure(borderwidth="2")
        self.summary_frame.configure(relief="groove")
        self.summary_frame.configure(background="#f0ece9")

        self.top_sum = tk.Label(self.summary_frame)
        self.top_sum.place(relx=0.0, rely=0.0, height=45, width=387)
        self.top_sum.configure(anchor='center')
        self.top_sum.configure(background="#f8d5c1")
        self.top_sum.configure(compound='left')
        self.top_sum.configure(disabledforeground="#a3a3a3")
        self.top_sum.configure(foreground="#000000")
        self.top_sum.configure(font=def_font)
        self.top_sum.configure(text='''Summary''')

        self.summary_lstbox = tk.Listbox(self.summary_frame)
        self.summary_lstbox.place(relx=0.0, rely=0.142, relheight=0.884
                , relwidth=1.0)
        self.summary_lstbox.configure(background="white")
        self.summary_lstbox.configure(cursor="fleur")
        self.summary_lstbox.configure(disabledforeground="#a3a3a3")
        self.summary_lstbox.configure(font=def_font)
        self.summary_lstbox.configure(foreground="#000000")

        self.summary_lstbox.insert(END, "Apartment's name: " + s_apartment.name)
        self.summary_lstbox.insert(END, "Apartment's address: " + order_support.tuple_to_string(s_apartment.area))
        self.summary_lstbox.insert(END, "Check-in date: " + str(search_details[0]))
        self.summary_lstbox.insert(END, "Check-out date: " + str(search_details[1]))
        self.summary_lstbox.insert(END, "Number of guests: " + str(search_details[2]))
        self.summary_lstbox.insert(END, "Number of Nights: " + str(days))
        self.summary_lstbox.insert(END, "Total Price: " + str(search_details[-1].price * days))


        self.timer_lbl = tk.Label(self.Frame1)
        self.timer_lbl.place(relx=0.75, rely=0.0, height=51, width=199)
        self.timer_lbl.configure(anchor='w')
        self.timer_lbl.configure(background="#de549a")
        self.timer_lbl.configure(compound='left')
        self.timer_lbl.configure(disabledforeground="#a3a3a3")
        self.timer_lbl.configure(foreground="#000000")
        self.timer_lbl.configure(font=def_font)
        self.timer_lbl.configure(text='''60s to go''')

        self.form_frame = tk.Frame(self.Frame1)
        self.form_frame.place(relx=0.014, rely=0.111, relheight=0.878
                , relwidth=0.481)
        self.form_frame.configure(relief='groove')
        self.form_frame.configure(borderwidth="2")
        self.form_frame.configure(relief="groove")
        self.form_frame.configure(background="#f8d5c1")

        self.Label1 = tk.Label(self.form_frame)
        self.Label1.place(relx=0.026, rely=0.025, height=31, width=144)
        self.Label1.configure(anchor='w')
        self.Label1.configure(background="#f0ece9")
        self.Label1.configure(compound='left')
        self.Label1.configure(disabledforeground="#a3a3a3")
        self.Label1.configure(foreground="#000000")
        self.Label1.configure(font=def_font)
        self.Label1.configure(text='''Full Name:''')

        self.full_name = tk.Entry(self.form_frame)
        self.full_name.place(relx=0.411, rely=0.025, height=30, relwidth=0.55)
        self.full_name.configure(background="white")
        self.full_name.configure(disabledforeground="#a3a3a3")
        self.full_name.configure(font=def_font)
        self.full_name.configure(foreground="#000000")
        self.full_name.configure(insertbackground="black")

        self.email = tk.Entry(self.form_frame)
        self.email.place(relx=0.411, rely=0.127, height=30, relwidth=0.55)
        self.email.configure(background="white")
        self.email.configure(disabledforeground="#a3a3a3")
        self.email.configure(font=def_font)
        self.email.configure(foreground="#000000")
        self.email.configure(highlightbackground="#d9d9d9")
        self.email.configure(highlightcolor="black")
        self.email.configure(insertbackground="black")
        self.email.configure(selectbackground="blue")
        self.email.configure(selectforeground="white")
        if logged:
            self.email.insert(0, logged.email)
            self.email.configure(state='disabled')

        self.Label1_1 = tk.Label(self.form_frame)
        self.Label1_1.place(relx=0.026, rely=0.127, height=31, width=144)
        self.Label1_1.configure(activebackground="#f3f3f3")
        self.Label1_1.configure(activeforeground="black")
        self.Label1_1.configure(anchor='w')
        self.Label1_1.configure(background="#f0ece9")
        self.Label1_1.configure(compound='left')
        self.Label1_1.configure(disabledforeground="#a3a3a3")
        self.Label1_1.configure(foreground="#000000")
        self.Label1_1.configure(font=def_font)
        self.Label1_1.configure(highlightbackground="#d9d9d9")
        self.Label1_1.configure(highlightcolor="black")
        self.Label1_1.configure(text='''Email Adress:''')

        self.credit_card_number = tk.Entry(self.form_frame)
        self.credit_card_number.place(relx=0.411, rely=0.278, height=30
                , relwidth=0.55)
        self.credit_card_number.configure(background="white")
        self.credit_card_number.configure(disabledforeground="#a3a3a3")
        self.credit_card_number.configure(font=def_font)
        self.credit_card_number.configure(foreground="#000000")
        self.credit_card_number.configure(highlightbackground="#d9d9d9")
        self.credit_card_number.configure(highlightcolor="black")
        self.credit_card_number.configure(insertbackground="black")
        self.credit_card_number.configure(selectbackground="blue")
        self.credit_card_number.configure(selectforeground="white")

        self.Label1_1_1 = tk.Label(self.form_frame)
        self.Label1_1_1.place(relx=0.026, rely=0.278, height=31, width=144)
        self.Label1_1_1.configure(activebackground="#f3f3f3")
        self.Label1_1_1.configure(activeforeground="black")
        self.Label1_1_1.configure(anchor='w')
        self.Label1_1_1.configure(background="#f0ece9")
        self.Label1_1_1.configure(compound='left')
        self.Label1_1_1.configure(disabledforeground="#a3a3a3")
        self.Label1_1_1.configure(foreground="#000000")
        self.Label1_1_1.configure(font=def_font)
        self.Label1_1_1.configure(highlightbackground="#d9d9d9")
        self.Label1_1_1.configure(highlightcolor="black")
        self.Label1_1_1.configure(text='''Credit card number:''')

        self.expiration_date = tk.Entry(self.form_frame)
        self.expiration_date.place(relx=0.411, rely=0.38, height=30
                , relwidth=0.55)
        self.expiration_date.configure(background="white")
        self.expiration_date.configure(disabledforeground="#a3a3a3")
        self.expiration_date.configure(font=def_font)
        self.expiration_date.configure(foreground="#000000")
        self.expiration_date.configure(highlightbackground="#d9d9d9")
        self.expiration_date.configure(highlightcolor="black")
        self.expiration_date.configure(insertbackground="black")
        self.expiration_date.configure(selectbackground="blue")
        self.expiration_date.configure(selectforeground="white")

        self.Label1_1_1_1 = tk.Label(self.form_frame)
        self.Label1_1_1_1.place(relx=0.026, rely=0.38, height=31, width=144)
        self.Label1_1_1_1.configure(activebackground="#f3f3f3")
        self.Label1_1_1_1.configure(activeforeground="black")
        self.Label1_1_1_1.configure(anchor='w')
        self.Label1_1_1_1.configure(background="#f0ece9")
        self.Label1_1_1_1.configure(compound='left')
        self.Label1_1_1_1.configure(disabledforeground="#a3a3a3")
        self.Label1_1_1_1.configure(foreground="#000000")
        self.Label1_1_1_1.configure(font=def_font)
        self.Label1_1_1_1.configure(highlightbackground="#d9d9d9")
        self.Label1_1_1_1.configure(highlightcolor="black")
        self.Label1_1_1_1.configure(text='''Expiration date:''')

        self.cvv = tk.Entry(self.form_frame)
        self.cvv.place(relx=0.411, rely=0.481, height=30, relwidth=0.55)
        self.cvv.configure(background="white")
        self.cvv.configure(disabledforeground="#a3a3a3")
        self.cvv.configure(font=def_font)
        self.cvv.configure(foreground="#000000")
        self.cvv.configure(highlightbackground="#d9d9d9")
        self.cvv.configure(highlightcolor="black")
        self.cvv.configure(insertbackground="black")
        self.cvv.configure(selectbackground="blue")
        self.cvv.configure(selectforeground="white")

        self.Label1_1_1_1_1 = tk.Label(self.form_frame)
        self.Label1_1_1_1_1.place(relx=0.026, rely=0.481, height=31, width=144)
        self.Label1_1_1_1_1.configure(activebackground="#f3f3f3")
        self.Label1_1_1_1_1.configure(activeforeground="black")
        self.Label1_1_1_1_1.configure(anchor='w')
        self.Label1_1_1_1_1.configure(background="#f0ece9")
        self.Label1_1_1_1_1.configure(compound='left')
        self.Label1_1_1_1_1.configure(disabledforeground="#a3a3a3")
        self.Label1_1_1_1_1.configure(foreground="#000000")
        self.Label1_1_1_1_1.configure(font=def_font)
        self.Label1_1_1_1_1.configure(highlightbackground="#d9d9d9")
        self.Label1_1_1_1_1.configure(highlightcolor="black")
        self.Label1_1_1_1_1.configure(text='''CCV:''')

        self.Label2 = tk.Label(self.form_frame)
        self.Label2.place(relx=0.026, rely=0.633, height=131, width=364)
        self.Label2.configure(anchor='center')
        self.Label2.configure(background="#f0ece9")
        self.Label2.configure(compound='left')
        self.Label2.configure(disabledforeground="#a3a3a3")
        self.Label2.configure(foreground="#000000")
        self.Label2.configure(font=title_font)
        self.Label2.configure(text='''TempHouse Services''')

        self.order_but = tk.Button(self.Frame1)
        self.order_but.place(relx=0.507, rely=0.8, height=84, width=197)
        self.order_but.configure(activebackground="#ececec")
        self.order_but.configure(activeforeground="#000000")
        self.order_but.configure(background="#244244")
        self.order_but.configure(compound='left')
        self.order_but.configure(disabledforeground="#a3a3a3")
        self.order_but.configure(foreground="#ffffff")
        self.order_but.configure(font=but_font)
        self.order_but.configure(highlightbackground="#d9d9d9")
        self.order_but.configure(highlightcolor="black")
        self.order_but.configure(pady="0")
        self.order_but.configure(text='''Rent !''')

        #     reservation = [full_name.get(), email.get(), str(search_details[0]), str(search_details[1]), str(search_details[2]), logged_user.id if logged_user else None]

        self.cancel_but = tk.Button(self.Frame1)
        self.cancel_but.place(relx=0.766, rely=0.8, height=84, width=177)
        self.cancel_but.configure(activebackground="#ececec")
        self.cancel_but.configure(activeforeground="#ffffff")
        self.cancel_but.configure(background="#244244")
        self.cancel_but.configure(compound='left')
        self.cancel_but.configure(disabledforeground="#a3a3a3")
        self.cancel_but.configure(foreground="#ffffff")
        self.cancel_but.configure(highlightbackground="#d9d9d9")
        self.cancel_but.configure(highlightcolor="black")
        self.cancel_but.configure(pady="0")
        self.cancel_but.configure(font=but_font)
        self.cancel_but.configure(text='''Cancel''')
        self.cancel_but.configure(command=lambda : (self.top.destroy(), order_support.end_session(client_socket, s_apartment)))

        #_thread.start_new_thread(func_dict["listen_to_afk"], (s_apartment, self.order_but, self.top))
        t = threading.Thread(target=func_dict["listen_to_afk"], args=(s_apartment, self.order_but, self.Frame1))
        t.start()
        #func_dict["listen_to_afk"](s_apartment, self.order_but, self.top)

        self.order_but.configure(command=lambda: func_dict.get("book_room")(s_apartment,
                                                                            order_support.make_reservation(
                                                                                self.full_name.get(), self.email.get(),
                                                                                search_details, logged), top))


def start_up(s_apartment, search_details, days, func_dict, logged, client_socket):
    order_support.main(s_apartment, search_details, days, func_dict, logged, client_socket)

