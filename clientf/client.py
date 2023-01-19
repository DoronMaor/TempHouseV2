import os
import time
from socket import *
import pickle
import Apartment
from tkHelper import *
import datetime
import _thread
import clientf.tk_frames.main_page as m_page
import clientf.tk_frames.apartments as apt_page
import clientf.tk_frames.order_page as order_page
import clientf.tk_frames.profile_page as profile_page
import clientf.tk_frames.login_page as login_page
import clientf.tk_frames.rating_page as rating_page
import clientf.tk_frames.admin_page as admin_page
import clientf.tk_frames.search_page as search_page
import clientf.tk_frames.upload_page as upload_page


def main_screen(frame=None, win=None, mes=None):
    # Main screen
    global logged_user, today
    if win:
        win.destroy()

    if today != datetime.date.today():
        mes2 = "Admin has changed the date to " + str(today) + "!"
    else:
        mes2 = None

    p = m_page.start_up(frame, logged_user, func_dict, mes, mes2)


def search_server(price, sdate, edate, place, people, frame=None, top=None):
    """
    Sends the search request to the server.
    """
    global search_details

    if not number_validation(price):
        pop_up(frame, "Price must be a number!")
        return
    else:
        price = 1301 if price == "" else int(price)

    try:
        sdate = datetime.date.fromisoformat("2022-01-01") if not sdate else datetime.date.fromisoformat(sdate)
    except:
        pop_up(frame, "Start date must be in the format YYYY-MM-DD!")
        return
    try:
        edate = datetime.date.fromisoformat("2023-01-01") if not edate else datetime.date.fromisoformat(edate)
    except:
        pop_up(frame, "End date must be in the format YYYY-MM-DD!")
        return


    if sdate > edate:
        pop_up(frame, "Start date must be before end date!")
        return
    if sdate < datetime.date.today():
        pop_up(frame, "Start date must be today or later!")
        return

    place = "(1,1)" if place == "" else place.replace(" ", "")

    if not number_validation(people):
        pop_up(frame, "People must be a number!")
        return
    else:
        people = 1 if people == "" else int(people)

    search_details = [sdate, edate, people]

    data = send_and_receive(("search", price, sdate, edate, place, people), 1024*30)

    if data[0] == "search_results":
        houses = data[1]
        # if the response is empty, the server did not find any houses
        if not houses:
            pop_up(frame, "No houses found!")
        else:
            # if the response is not empty, the server found some houses
            search_apartments_window(houses, place, frame, top)
    else:
        pop_up(frame, "Error while searching!")


def search_apartments_window(houses, area, frame=None, win=None):
    p = apt_page.start_up(frame, logged_user, func_dict, houses, area, None, win)


def get_pics(ap_id):
    """
    Sends the request to the server to get the pictures of the apartment
    """
    th = "temps/%d.png" % ap_id
    error_path = "pics/error.png"
    full_path = os.path.abspath(th)
    error_path = os.path.abspath(error_path)

    data = send_and_receive(("get_pics", ap_id), 1024*310)

    if data[0] == "pics":
        if not data[1]:
            return (full_path, error_path)
        if os.path.exists(th):
            os.remove(th)
        try:
            with open(th, "wb") as f:
                for d in data[1]:
                    f.write(d)
        except:
            pass

    return (full_path, error_path)


def connect_to_server():
    """
    Connects to the server.
    """
    global today

    s = socket(AF_INET, SOCK_STREAM)
    s.connect(("localhost", 7777))
    # receiving the response from the server
    s.send(pickle.dumps(("get_date", None)))
    while True:
        try:
            data = s.recv(902 * 15)
            data = pickle.loads(data)
        except:
            return
        if data[0] == "date":
            break
    today = data[1]
    return s


def profile_window(frame=None, win=None, mes=None):
    """
    Opens the profile window.
    """
    if logged_user is None:
        pop_up(frame, "You must be logged in to view your profile!")
        return
    if logged_user:
        silent_login(log_username, log_pass)

    p = profile_page.start_up(frame, logged_user, func_dict, mes)


def home_button(frame, top=None):
    """
    Function that creates the home button
    :param frame: frame where the button will be placed
    :param logged: if the user is logged in or not
    :return: None
    """
    btn_home = Button(frame, text="Home",
                      command=lambda: main_screen(frame, top), font=def_font)
    btn_home.pack(side=LEFT, expand="YES", fill="both")


def book_window(frame, top, s_apartment, houses):
    global search_details, func_dict
    s_apartment = find_house_by_name(s_apartment, houses)
    search_details.append(s_apartment)
    days = (search_details[1] - search_details[0]).days
    #cur_time = datetime.datetime.now()
    #client_socket.send(pickle.dumps(("start_rent", s_apartment.id, cur_time)))
    b = order_page.start_up(s_apartment, search_details, days, func_dict, logged_user, client_socket)


def send_afk(ap):
    cur_time = datetime.datetime.now()
    send_and_receive(("start_rent", ap.id, cur_time), 1024 * 30)


def listen_to_afk(s_apartment, button, top):
    global afk
    """
    cur_time = datetime.datetime.now()
    response = send_and_receive(("start_rent", s_apartment.id, cur_time), 1024*30)
    client_socket.send(pickle.dumps(("start_rent", s_apartment.id, cur_time)))
    if response[0] == "afk_rent":
        button.config(state="disabled")
    else:
    """
    time.sleep(9.5)
    print("afk")
    if afk:
        res = client_socket.recv(1024*30)
        res = pickle.loads(res)
        if res[0] == "afk_rent":
            afk_window(top, s_apartment)
        else:
            pass
    afk = True


def afk_window(top, s_apartment):
    global search_details, func_dict
    try:
        top.destroy()
    except:
        pass

def book_room(s_apartment, reservation=None, top=None, send=True, response=None, th=None):
    global afk
    afk = False
    try:
        top.destroy()
    except:
        pass
    respose = send_and_receive(mes=("book", s_apartment.id, reservation, logged_user.id if logged_user else None),
                                buffer_size=1024 * 10)
    if respose[0] == "booked":
        pop_up(1, "You have successfully booked the apartment!", True)
    else:
        pop_up(1, "Error while booking the apartment!", True)


def find_house_by_name(name, houses):
    """
    Finds a house by its name.
    """

    for house in houses:
        if house.name == name:
            return house


def login_window(top):
    """
    Opens the login window.
    """
    global logged_user

    if logged_user is not None:
        logged_user = None
        top.destroy()
        main_screen(None, None, "You have been logged out.")

    else:
        l = login_page.start_up(func_dict, top)


def login_server(username, password, frame, top):
    """
    Logs the user in the server.
    """
    global logged_user, log_username, log_pass
    login_state = False

    # send the username and password to the server
    try:
        response = send_and_receive(mes=("login", username, password), buffer_size=1024 * 10)
        if response[0] == "login_success":
            logged_user = response[1]
            log_username = username
            log_pass = password
            login_state = True
            frame.destroy()
            top.destroy()
            main_screen(None, None, "You have been logged in.")
        else:
            pop_up(top, "Wrong username or password.")
    except:
        pop_up(top, "An error occurred. Please try again.")
        frame.destroy()
        return


def silent_login(username, password):
    """
    Logs the user in the server.
    """
    global logged_user
    login_state = False

    # send the username and password to the server
    try:
        client_socket.send(pickle.dumps(("login", username, password)))
        response = send_and_receive(mes=("login", username, password), buffer_size=4069*2)
        if response[0] == "login_success":
            logged_user = response[1]
            login_state = True
        else:
            return False
    except:
        return False


def email_validation(email):
    if re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return True
    else:
        return False


def number_validation(number):
    if number == "":
        return False
    if re.match(r"^[0-9]*$", number):
        return True
    else:
        return False


def register_server(username, password, email, id, age, ref_code, frame, top):
    # send the info to the server
    if not email_validation(email):
        pop_up(top, "Invalid email address.")
        return

    if not number_validation(id):
        pop_up(top, "Invalid ID number.")
        return

    if not number_validation(age):
        pop_up(top, "Invalid age.")
        return

    id = int(id)
    age = int(age)
    try:
        client_socket.send(pickle.dumps(("register", username, password, email, age, ref_code, id)))
        response = send_and_receive(mes=("register", username, password, email, age, ref_code, id), buffer_size=4069*2)
        if response[0] == "success":
            frame.destroy()
            top.destroy()
            main_screen(None, None, response[1])
        else:
            pop_up(top, response[1])
    except:
        pop_up(top, "An error occurred. Please try again.")


def get_apartment_by_id(id):
    """
    Sends a request to the server to get an apartment by its id.
    """
    response = send_and_receive(mes=("find_apartment_by_id", id), buffer_size=4069*2)
    return response


def cancel_reservation(user_id, apartment_id, frame, top):
    """
    Sends a request to the server to cancel a reservation.
    """

    apartment_id = apartment_id.split('[')[1].split(']')[0]
    try:
        client_socket.send(pickle.dumps(("cancel_reservation", user_id, apartment_id)))
        response = send_and_receive(mes=("cancel_reservation", user_id, apartment_id), buffer_size=4069 * 2)
        if response[0] == "reserv":
            top.destroy()
            profile_window(None, None, response[1])
    except:
        pop_up(top, "An error occurred. Please try again.")
        return


def rate_apartment_window(apartment_id, frame, top, test):
    # is apartment_id contains " [Rated]"
    if " [Rated]" in apartment_id:
        pop_up(top, "You have already rated this apartment.")
        return

    apartment_id = apartment_id.split('[')[1].split(']')[0]

    r = rating_page.start_up(apartment_id, frame, func_dict, top)


def rate_apartment_server(apartment_id, comment, stars, top):
    """
    Sends a request to the server to rate an apartment.
    """
    user_id = logged_user.id
    dbu_rating = [apartment_id, stars, comment]
    dba_rating = [user_id, stars, comment]

    try:
        apartment_id = int(apartment_id)
        response = send_and_receive(mes=("rate_apartment", dbu_rating, dba_rating, logged_user), buffer_size=4069 * 2)
        if response[0] == "rate":
            popup_function(top, "You have successfully rated this apartment.", top.destroy, "OK")
        else:
            pop_up(top, response[1])
    except:
        pop_up(top, "An error occurred. Please try again.")
        return


def admin_window(frame, top, clicked):
    global logged_user, func_dict
    # if clicked conatins the word "Admin" 2 times
    if clicked.count("Admin") == 2 or clicked == "None" * 100:
        if logged_user:
            if logged_user.is_admin:
                a = admin_page.start_up(frame, func_dict, logged_user, top)
            else:
                pop_up(top, "You are not an admin.")
        else:
            pop_up(top, "You are not logged in.")


def get_all_apartments():
    """
    Sends a request to the server to get all apartments.
    """
    try:
        response = send_and_receive(mes=("find_apartment_by_id", None), buffer_size=4069*2)
        return response
    except:
        return None


def set_attractions(attractions_file, top):
    """
    Sends a request to the server to set the attractions.
    """
    if logged_user:
        if not logged_user.is_admin:
            return
        else:
            try:
                response = send_and_receive(mes=("set_attractions", attractions_file), buffer_size=4069*2)
                if response[0] == "set":
                    pop_up(top, "You have successfully set the attractions.")
                    return
                else:
                    return response[1]
            except:
                return None
    else:
        return "You are not logged in."


def get_attractions():
    """
    Sends a request to the server to get the attractions.
    """
    try:
        response = send_and_receive(mes=("get_attractions", None), buffer_size=4069*2)

        return response[1]
    except:
        return None


def search_admin_window(frame, top):
    s = search_page.start_up(frame, func_dict, top)


def get_specific_user_resvs(user_id, past, active):
    """
    Sends a request to the server to get the reservations of a specific user.
    """
    try:
        response = send_and_receive(mes=("get_specific_user_resvs", user_id), buffer_size=4069 * 2)

        if response is None:
            return None

        if response[0] == "res":
            return response[1]

        return None

    except:
        return None


def upload_apartment_window(frame, top):
    if not logged_user:
        pop_up(top, "You are not logged in.")
        return
    else:
        u = upload_page.start_up(frame, func_dict, logged_user, top)


def upload_apartment_server(top, entry_name, entry_price, entry_num_rooms, entry_num_beds, entry_images,
                            entry_description, entry_location, entry_owner, entry_rules):
    name = entry_name.get()
    price = int(entry_price.get())
    num_rooms = int(entry_num_rooms.get())
    num_beds = int(entry_num_beds.get())
    im_path = entry_images.get()
    location = entry_location.get()
    owner = int(entry_owner.get())
    description = entry_description.get("1.0", END)
    rules = entry_rules.get("1.0", END)

    # get image from path
    try:
        with open(im_path, "rb") as f:
            img = f.readlines()
    except:
        pop_up(top, "The image path is not valid.")
        return
    try:
        res = send_and_receive(mes=("save_image", img, "unnamed"), buffer_size=4069 * 2)
        if res[0] == "saved":
            img_path = res[1]
        else:
            pop_up(top, "The image could not be saved.")
            return
    except:
        pop_up(top, "The image could not be saved.")
        return

    ap = Apartment.Apartment(name, num_rooms, num_beds, price, img_path, description, rules, location, owner)
    response = send_and_receive(mes=("upload", pickle.dumps(ap)), buffer_size=4069 * 2)
    if response[0] == 'upload_success':
        popup_function(top, "Apartment uploaded successfully.", top.destroy, "OK")
    else:
        pop_up(top, "Error, could not add apartment. Please try again")


def get_date():
    return today


def set_date(dat, top):
    global today
    try:
        # turn date into datetime object
        d = datetime.datetime.strptime(dat, '%Y-%m-%d')
        response = send_and_receive(mes=("set_date", d), buffer_size=4069)
        if response[0] == "date":
            today = response[1]
            pop_up(top, "Date set successfully.")
            return
        else:
            return response[1]
    except Exception as e:
        pop_up(top, "Please enter a valid date." + str(e))
        return


def send_and_receive(mes, buffer_size):
    pickled_mes = pickle.dumps(mes)
    client_socket.send(pickled_mes)
    return pickle.loads(client_socket.recv(buffer_size))


def on_close(root):
    """
    When the window is closed, send a message to the server to close the connection
    """
    mes = ("close", "")
    mes = pickle.dumps(mes)
    try:
        client_socket.send(mes)
        client_socket.close()
    except:
        pass
    clear_temp_files()
    root.destroy()


def clear_temp_files():
    """
    Clears all the temp files in the temp folder.
    """
    temp_path = os.path.join(os.getcwd(), "temps")
    try:
        for file in os.listdir(temp_path):
            if file.endswith(".png"):
                os.remove(os.path.join(temp_path, file))
    except:
        pass


# --------------------------------------------------


"""
# Tkinter
root = root_window()
x = root.winfo_screenwidth()
y = root.winfo_screenheight()

# current session
logged_user = None
search_details = ["check-in", "check-out", "guests", "apartment"]

# sockets
client_socket = connect_to_server()
buffer_size = 1024

client_start_window()

root.mainloop()
"""
# current session
logged_user = None
log_username = None
log_pass = None
search_details = ["check-in", "check-out", "guests", "apartment"]
today = datetime.datetime.today().date()
afk = True

# sockets
client_socket = connect_to_server()
buffer_size = 2048

func_dict = {
    "main_screen": main_screen,
    "search_server": search_server,
    "login_window": login_window,
    "profile_window": profile_window,
    "get_pics": get_pics,
    "book_window": book_window,
    "book_room": book_room,
    "login_server": login_server,
    "register_server": register_server,
    "get_apartment_by_id": get_apartment_by_id,
    "cancel_reservation": cancel_reservation,
    "rate_apartment_window": rate_apartment_window,
    "rate_apartment_server": rate_apartment_server,
    "admin_window": admin_window,
    "get_all_apartments": get_all_apartments,
    "set_attractions": set_attractions,
    "get_attractions": get_attractions,
    "search_admin_window": search_admin_window,
    "get_specific_user_resvs": get_specific_user_resvs,
    "upload_apartment_window": upload_apartment_window,
    "on_close": on_close,
    "listen_to_afk": listen_to_afk,
    "get_date": get_date,
    "set_date": set_date,
    "upload_apartment_server": upload_apartment_server,
    "send_afk": send_afk,
}

main_screen()
# 1160
# 760
