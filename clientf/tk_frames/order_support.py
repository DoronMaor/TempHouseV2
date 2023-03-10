#! /usr/bin/env python
#  -*- coding: utf-8 -*-
#
# Support module generated by PAGE version 7.3
#  in conjunction with Tcl version 8.6
#    Apr 30, 2022 04:56:09 PM +0300  platform: Windows NT
import _thread
import pickle
import tkinter as tk

import clientf.tk_frames.order_page as order


def main(s_apartment, search_details, days, func_dict, logged, client_socket, *args):
    '''Main entry point for the application.'''
    global root
    root = tk.Tk()
    root.protocol( 'WM_DELETE_WINDOW' , lambda: end_session(client_socket, s_apartment))
    # Creates a toplevel widget.
    global _top1, _w1
    _top1 = root
    func_dict["send_afk"](s_apartment)
    _w1 = order.renting_page(s_apartment, search_details, days, func_dict, logged, client_socket, _top1)
    root.mainloop()

def end_session(client_socket, s_apartment, *args):
    '''
    Ends the session.
    '''
    #client_socket.send(pickle.dumps(("end_rent", s_apartment.id)))


def tuple_to_string(tuple):
    return "(%s, %s)" % (tuple[0], tuple[1])


def make_reservation(name, email, search_details, user, *args):
    '''
    Makes a reservation.
    '''
    reservation = [name, email, str(search_details[0]), str(search_details[1]), str(search_details[2]), user.id if user else None]
    return reservation


