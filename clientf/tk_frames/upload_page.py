import sys
import tkinter as tk
import tkinter.ttk as ttk
from tkinter.constants import *

import clientf.tk_frames.upload_page_support as upload_page_support

class upload_win:
    def __init__(self, frame, func_dict, logged, top=None):
        '''This class configures and populates the toplevel window.
           top is the toplevel containing window.'''
        _bgcolor = '#eaddda'  # X11 color: 'gray85'
        _fgcolor = '#000000'  # X11 color: 'black'
        _compcolor = '#eaddda' # X11 color: 'gray85'
        _ana1color = '#eaddda' # X11 color: 'gray85'
        _ana2color = '#ececec' # Closest X11 color: 'gray92'
        title_font = ("Verdana", 16, 'bold')
        def_font = ("Verdana", 12,)
        but_font = ("Arial Black", 11)


        top.geometry("1160x760")
        top.minsize(120, 1)
        top.maxsize(3604, 1061)
        top.resizable(1,  1)
        top.title("Upload")
        top.configure(background="#eaddda")
        top.iconbitmap(r'pics/icon.ico')
        self.top = top

        self.Frame1 = tk.Frame(self.top)
        self.Frame1.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.Frame1.configure(relief='groove')
        self.Frame1.configure(borderwidth="2")
        self.Frame1.configure(relief="groove")
        self.Frame1.configure(background="#f0ece9")

        self.name_lbl = tk.Label(self.Frame1)
        self.name_lbl.place(relx=0.009, rely=0.066, height=41, width=265)
        self.name_lbl.configure(anchor='w')
        self.name_lbl.configure(background="#f8d5c1")
        self.name_lbl.configure(compound='left')
        self.name_lbl.configure(disabledforeground="#a3a3a3")
        self.name_lbl.configure(foreground="#000000")
        self.name_lbl.configure(font=def_font)
        self.name_lbl.configure(text='''Name:''')

        self.num_rooms_lbl = tk.Label(self.Frame1)
        self.num_rooms_lbl.place(relx=0.009, rely=0.132, height=41, width=265)
        self.num_rooms_lbl.configure(activebackground="#f9f9f9")
        self.num_rooms_lbl.configure(activeforeground="black")
        self.num_rooms_lbl.configure(anchor='w')
        self.num_rooms_lbl.configure(background="#f8d5c1")
        self.num_rooms_lbl.configure(compound='left')
        self.num_rooms_lbl.configure(disabledforeground="#a3a3a3")
        self.num_rooms_lbl.configure(foreground="#000000")
        self.num_rooms_lbl.configure(highlightbackground="#eaddda")
        self.num_rooms_lbl.configure(highlightcolor="black")
        self.num_rooms_lbl.configure(font=def_font)
        self.num_rooms_lbl.configure(text='''Number of rooms''')

        self.lbl_people = tk.Label(self.Frame1)
        self.lbl_people.place(relx=0.009, rely=0.197, height=41, width=265)
        self.lbl_people.configure(activebackground="#f9f9f9")
        self.lbl_people.configure(activeforeground="black")
        self.lbl_people.configure(anchor='w')
        self.lbl_people.configure(background="#f8d5c1")
        self.lbl_people.configure(compound='left')
        self.lbl_people.configure(disabledforeground="#a3a3a3")
        self.lbl_people.configure(foreground="#000000")
        self.lbl_people.configure(highlightbackground="#eaddda")
        self.lbl_people.configure(highlightcolor="black")
        self.lbl_people.configure(font=def_font)
        self.lbl_people.configure(text='''Maximum people:''')

        self.price_lbl = tk.Label(self.Frame1)
        self.price_lbl.place(relx=0.509, rely=0.066, height=41, width=265)
        self.price_lbl.configure(activebackground="#f9f9f9")
        self.price_lbl.configure(activeforeground="black")
        self.price_lbl.configure(anchor='w')
        self.price_lbl.configure(background="#f8d5c1")
        self.price_lbl.configure(compound='left')
        self.price_lbl.configure(disabledforeground="#a3a3a3")
        self.price_lbl.configure(foreground="#000000")
        self.price_lbl.configure(highlightbackground="#eaddda")
        self.price_lbl.configure(highlightcolor="black")
        self.price_lbl.configure(font=def_font)
        self.price_lbl.configure(text='''Price per day [ILS]:''')

        self.lbl_owner = tk.Label(self.Frame1)
        self.lbl_owner.place(relx=0.509, rely=0.132, height=41, width=265)
        self.lbl_owner.configure(activebackground="#f9f9f9")
        self.lbl_owner.configure(activeforeground="black")
        self.lbl_owner.configure(anchor='w')
        self.lbl_owner.configure(background="#f8d5c1")
        self.lbl_owner.configure(compound='left')
        self.lbl_owner.configure(disabledforeground="#a3a3a3")
        self.lbl_owner.configure(foreground="#000000")
        self.lbl_owner.configure(highlightbackground="#eaddda")
        self.lbl_owner.configure(highlightcolor="black")
        self.lbl_owner.configure(font=def_font)
        self.lbl_owner.configure(text='''Owner:''')

        self.entry_location = tk.Entry(self.Frame1)
        self.map_lunch = tk.Button(self.Frame1)
        self.map_lunch.place(relx=0.509, rely=0.197, height=44, width=507)
        self.map_lunch.configure(activebackground="#ececec")
        self.map_lunch.configure(activeforeground="#000000")
        self.map_lunch.configure(background="#de549a")
        self.map_lunch.configure(compound='left')
        self.map_lunch.configure(disabledforeground="#a3a3a3")
        self.map_lunch.configure(foreground="#000000")
        self.map_lunch.configure(highlightbackground="#eaddda")
        self.map_lunch.configure(highlightcolor="black")
        self.map_lunch.configure(pady="0")
        self.map_lunch.configure(font=but_font)
        self.map_lunch.configure(text='''Map''')
        self.map_lunch.configure(command=lambda: upload_page_support.apartments_map(self.entry_location, self.map_lunch, func_dict))

        self.Frame2 = tk.Frame(self.Frame1)
        self.Frame2.place(relx=0.009, rely=0.276, relheight=0.021
                , relwidth=0.972)
        self.Frame2.configure(relief='groove')
        self.Frame2.configure(borderwidth="2")
        self.Frame2.configure(relief="groove")
        self.Frame2.configure(background="#eaddda")

        self.Frame2_1 = tk.Frame(self.Frame2)
        self.Frame2_1.place(relx=0.15, rely=31.375, relheight=1.0, relwidth=1.0)
        self.Frame2_1.configure(relief='groove')
        self.Frame2_1.configure(borderwidth="2")
        self.Frame2_1.configure(relief="groove")
        self.Frame2_1.configure(background="#eaddda")
        self.Frame2_1.configure(highlightbackground="#eaddda")
        self.Frame2_1.configure(highlightcolor="black")

        self.top_lbl = tk.Label(self.Frame1)
        self.top_lbl.place(relx=0.0, rely=0.0, height=41, width=1160)
        self.top_lbl.configure(background="#eaddda")
        self.top_lbl.configure(compound='left')
        self.top_lbl.configure(disabledforeground="#a3a3a3")
        self.top_lbl.configure(foreground="#000000")
        self.top_lbl.configure(font=title_font)
        self.top_lbl.configure(text='''Upload your Apartment''')

        self.lbl_description = tk.Label(self.Frame1)
        self.lbl_description.place(relx=0.009, rely=0.329, height=41, width=265)
        self.lbl_description.configure(activebackground="#f9f9f9")
        self.lbl_description.configure(activeforeground="black")
        self.lbl_description.configure(anchor='w')
        self.lbl_description.configure(background="#f8d5c1")
        self.lbl_description.configure(compound='left')
        self.lbl_description.configure(disabledforeground="#a3a3a3")
        self.lbl_description.configure(foreground="#000000")
        self.lbl_description.configure(highlightbackground="#eaddda")
        self.lbl_description.configure(highlightcolor="black")
        self.lbl_description.configure(font=def_font)
        self.lbl_description.configure(text='''Description''')

        self.lbl_rules = tk.Label(self.Frame1)
        self.lbl_rules.place(relx=0.509, rely=0.329, height=41, width=265)
        self.lbl_rules.configure(activebackground="#f9f9f9")
        self.lbl_rules.configure(activeforeground="black")
        self.lbl_rules.configure(anchor='w')
        self.lbl_rules.configure(background="#f8d5c1")
        self.lbl_rules.configure(compound='left')
        self.lbl_rules.configure(disabledforeground="#a3a3a3")
        self.lbl_rules.configure(foreground="#000000")
        self.lbl_rules.configure(highlightbackground="#eaddda")
        self.lbl_rules.configure(highlightcolor="black")
        self.lbl_rules.configure(font=def_font)
        self.lbl_rules.configure(text='''Rules [seperate by ',']''')

        self.entry_description = tk.Text(self.Frame1)
        self.entry_description.place(relx=0.009, rely=0.408, relheight=0.203
                , relwidth=0.443)
        self.entry_description.configure(background="white")
        self.entry_description.configure(font=def_font)
        self.entry_description.configure(foreground="black")
        self.entry_description.configure(highlightbackground="#eaddda")
        self.entry_description.configure(highlightcolor="black")
        self.entry_description.configure(insertbackground="black")
        self.entry_description.configure(selectbackground="blue")
        self.entry_description.configure(selectforeground="white")
        self.entry_description.configure(wrap="word")

        self.entry_rules = tk.Text(self.Frame1)
        self.entry_rules.place(relx=0.509, rely=0.408, relheight=0.203
                , relwidth=0.453)
        self.entry_rules.configure(background="white")
        self.entry_rules.configure(font=def_font)
        self.entry_rules.configure(foreground="black")
        self.entry_rules.configure(highlightbackground="#eaddda")
        self.entry_rules.configure(highlightcolor="black")
        self.entry_rules.configure(insertbackground="black")
        self.entry_rules.configure(selectbackground="blue")
        self.entry_rules.configure(selectforeground="white")
        self.entry_rules.configure(wrap="word")

        self.Frame2_2 = tk.Frame(self.Frame1)
        self.Frame2_2.place(relx=0.009, rely=0.632, relheight=0.021
                , relwidth=0.972)
        self.Frame2_2.configure(relief='groove')
        self.Frame2_2.configure(borderwidth="2")
        self.Frame2_2.configure(relief="groove")
        self.Frame2_2.configure(background="#eaddda")
        self.Frame2_2.configure(highlightbackground="#eaddda")
        self.Frame2_2.configure(highlightcolor="black")

        self.Frame2_1_1 = tk.Frame(self.Frame2_2)
        self.Frame2_1_1.place(relx=0.15, rely=31.375, relheight=1.0
                , relwidth=1.0)
        self.Frame2_1_1.configure(relief='groove')
        self.Frame2_1_1.configure(borderwidth="2")
        self.Frame2_1_1.configure(relief="groove")
        self.Frame2_1_1.configure(background="#eaddda")
        self.Frame2_1_1.configure(highlightbackground="#eaddda")
        self.Frame2_1_1.configure(highlightcolor="black")

        self.lbl_images = tk.Label(self.Frame1)
        self.lbl_images.place(relx=0.009, rely=0.684, height=41, width=265)
        self.lbl_images.configure(activebackground="#f9f9f9")
        self.lbl_images.configure(activeforeground="black")
        self.lbl_images.configure(anchor='w')
        self.lbl_images.configure(background="#f8d5c1")
        self.lbl_images.configure(compound='left')
        self.lbl_images.configure(cursor="fleur")
        self.lbl_images.configure(disabledforeground="#a3a3a3")
        self.lbl_images.configure(foreground="#000000")
        self.lbl_images.configure(highlightbackground="#eaddda")
        self.lbl_images.configure(highlightcolor="black")
        self.lbl_images.configure(font=def_font)
        self.lbl_images.configure(text='''Image path:''')

        self.Frame3 = tk.Frame(self.Frame1)
        self.Frame3.place(relx=0.698, rely=0.671, relheight=0.245, relwidth=0.26)

        self.Frame3.configure(relief='groove')
        self.Frame3.configure(borderwidth="2")
        self.Frame3.configure(relief="groove")
        self.Frame3.configure(background="#eaddda")

        self.img_canvas = tk.Canvas(self.Frame3)
        self.img_canvas.place(relx=0.0, rely=0.0, relheight=1.0, relwidth=1.0)
        self.img_canvas.configure(background="#eaddda")
        self.img_canvas.configure(borderwidth="2")
        self.img_canvas.configure(insertbackground="black")
        self.img_canvas.configure(relief="ridge")
        self.img_canvas.configure(selectbackground="blue")
        self.img_canvas.configure(selectforeground="white")

        self.upload_btn = tk.Button(self.Frame1)
        self.upload_btn.place(relx=0.0, rely=0.947, height=44, width=580)
        self.upload_btn.configure(activebackground="#ececec")
        self.upload_btn.configure(activeforeground="#000000")
        self.upload_btn.configure(background="#de549a")
        self.upload_btn.configure(compound='left')
        self.upload_btn.configure(disabledforeground="#a3a3a3")
        self.upload_btn.configure(foreground="#000000")
        self.upload_btn.configure(highlightbackground="#eaddda")
        self.upload_btn.configure(highlightcolor="black")
        self.upload_btn.configure(pady="0")
        self.upload_btn.configure(font=but_font)
        self.upload_btn.configure(text='''Upload!''')
        self.upload_btn.configure(command=lambda: func_dict['upload_apartment_server']
        (self.top, self.entry_name, self.entry_price, self.entry_num_rooms, self.entry_num_beds, self.entry_images
         , self.entry_description, self.entry_location, self.entry_owner, self.entry_rules))

        self.cancel_btn = tk.Button(self.Frame1)
        self.cancel_btn.place(relx=0.5, rely=0.947, height=44, width=580)
        self.cancel_btn.configure(activebackground="#ececec")
        self.cancel_btn.configure(activeforeground="#000000")
        self.cancel_btn.configure(background="#de549a")
        self.cancel_btn.configure(compound='left')
        self.cancel_btn.configure(disabledforeground="#a3a3a3")
        self.cancel_btn.configure(foreground="#000000")
        self.cancel_btn.configure(highlightbackground="#eaddda")
        self.cancel_btn.configure(highlightcolor="black")
        self.cancel_btn.configure(pady="0")
        self.cancel_btn.configure(font=but_font)
        self.cancel_btn.configure(text='''Cancel''')
        self.cancel_btn.configure(command=self.top.destroy)

        self.entry_name = tk.Entry(self.Frame1)
        self.entry_name.place(relx=0.25, rely=0.066, height=43, relwidth=0.193)
        self.entry_name.configure(background="white")
        self.entry_name.configure(disabledforeground="#a3a3a3")
        self.entry_name.configure(font=def_font)
        self.entry_name.configure(foreground="#000000")
        self.entry_name.configure(insertbackground="black")

        self.entry_num_rooms = tk.Entry(self.Frame1)
        self.entry_num_rooms.place(relx=0.25, rely=0.132, height=43
                , relwidth=0.193)
        self.entry_num_rooms.configure(background="white")
        self.entry_num_rooms.configure(disabledforeground="#a3a3a3")
        self.entry_num_rooms.configure(font=def_font)
        self.entry_num_rooms.configure(foreground="#000000")
        self.entry_num_rooms.configure(highlightbackground="#eaddda")
        self.entry_num_rooms.configure(highlightcolor="black")
        self.entry_num_rooms.configure(insertbackground="black")
        self.entry_num_rooms.configure(selectbackground="blue")
        self.entry_num_rooms.configure(selectforeground="white")

        self.entry_num_beds = tk.Entry(self.Frame1)
        self.entry_num_beds.place(relx=0.25, rely=0.197, height=43
                , relwidth=0.193)
        self.entry_num_beds.configure(background="white")
        self.entry_num_beds.configure(disabledforeground="#a3a3a3")
        self.entry_num_beds.configure(font=def_font)
        self.entry_num_beds.configure(foreground="#000000")
        self.entry_num_beds.configure(highlightbackground="#eaddda")
        self.entry_num_beds.configure(highlightcolor="black")
        self.entry_num_beds.configure(insertbackground="black")
        self.entry_num_beds.configure(selectbackground="blue")
        self.entry_num_beds.configure(selectforeground="white")

        self.entry_price = tk.Entry(self.Frame1)
        self.entry_price.place(relx=0.75, rely=0.066, height=43, relwidth=0.193)
        self.entry_price.configure(background="white")
        self.entry_price.configure(disabledforeground="#a3a3a3")
        self.entry_price.configure(font=def_font)
        self.entry_price.configure(foreground="#000000")
        self.entry_price.configure(highlightbackground="#eaddda")
        self.entry_price.configure(highlightcolor="black")
        self.entry_price.configure(insertbackground="black")
        self.entry_price.configure(selectbackground="blue")
        self.entry_price.configure(selectforeground="white")

        self.entry_owner = tk.Entry(self.Frame1)
        self.entry_owner.place(relx=0.75, rely=0.132, height=43, relwidth=0.193)
        self.entry_owner.configure(background="white")
        self.entry_owner.configure(disabledforeground="#a3a3a3")
        self.entry_owner.configure(font=def_font)
        self.entry_owner.configure(foreground="#000000")
        self.entry_owner.configure(highlightbackground="#eaddda")
        self.entry_owner.configure(highlightcolor="black")
        self.entry_owner.configure(insertbackground="black")
        self.entry_owner.configure(selectbackground="blue")
        self.entry_owner.configure(selectforeground="white")
        self.entry_owner.insert(0, logged.id)
        self.entry_owner.configure(state='disabled')

        self.entry_images = tk.Entry(self.Frame1)
        self.entry_images.place(relx=0.25, rely=0.684, height=43, relwidth=0.366)

        self.entry_images.configure(background="white")
        self.entry_images.configure(disabledforeground="#a3a3a3")
        self.entry_images.configure(font=def_font)
        self.entry_images.configure(foreground="#000000")
        self.entry_images.configure(highlightbackground="#eaddda")
        self.entry_images.configure(highlightcolor="black")
        self.entry_images.configure(insertbackground="black")
        self.entry_images.configure(selectbackground="blue")
        self.entry_images.configure(selectforeground="white")
        # on typing in the entry box 
        self.entry_images.bind('<KeyRelease>', lambda event: upload_page_support.preview_image(self.entry_images, self.img_canvas))

        upload_page_support.preview_image(self.entry_images, self.img_canvas)

def start_up(frame, func_dict, logged, top):
    upload_page_support.main(frame, func_dict, logged, top)
