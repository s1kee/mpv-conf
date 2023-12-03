import requests
import tkinter as tk
from tkinter import messagebox

# Specify your Trakt.tv API credentials
client_id = '76a97838e5a04002f019218b1003f69419e5f72b57ba20f2aed9c4636cf83122'
client_secret = '34cbc718b56e77e79c235287e631ef1fac463375347369e291d79142d8fb1d8b'
access_token = '682d4503014aa1a04c1e3a3f54f265003830533eb8cbd6d18042c6b015cbdb80'

# Set the API endpoint for retrieving history
history_url = 'https://api.trakt.tv/sync/history'
# Set the API endpoint for adding ratings
ratings_url = 'https://api.trakt.tv/sync/ratings'

# Set the headers with necessary authentication and content type
headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {access_token}',
    'trakt-api-version': '2',
    'trakt-api-key': client_id
}

# Set the parameters to filter the history results
history_params = {
    'limit': 1,  # Retrieve only the latest item
    'type': 'episodes',  # Filter for episodes
    'action': 'checkin'
    
}

latest_episode = {}  # Define latest_episode as a global variable

def fetch_latest_history():
    global latest_episode  # Access the global variable

    # Send the GET request to retrieve the history
    history_response = requests.get(history_url, headers=headers, params=history_params)

    if history_response.status_code == 200:
        # Extract the latest watched episode from the response
        latest_episode = history_response.json()[0]

        # Access the relevant information (e.g., title, season, episode number)
        episode_title = latest_episode['episode']['title']
        season_number = latest_episode['episode']['season']
        episode_number = latest_episode['episode']['number']

        # Update the episode and season labels with the latest information
        episode_label.config(text=f"{episode_title}")
        season_label.config(text=f"Season: {season_number}  Episode: {episode_number}")
        rating_entry.focus_set()  # Set focus to the rating entry field
    else:
        print("Error retrieving history:", history_response.status_code)

def add_rating():
    global latest_episode  # Access the global variable

    # Get the rating from the entry
    rating = rating_entry.get()
    
    # Multiply the rating by two
    multiplied_rating = float(rating) * 2

    # Create the payload with the episode rating data
    rating_payload = {
        "episodes": [
            {
                "rating": multiplied_rating,
                "ids": {
                    "trakt": latest_episode['episode']['ids']['trakt'],
                    "tvdb": latest_episode['episode']['ids']['tvdb'],
                    "imdb": latest_episode['episode']['ids']['imdb'],
                    "tmdb": latest_episode['episode']['ids']['tmdb']
                }
            }
        ]
    }

    # Send the POST request to add the rating
    ratings_response = requests.post(ratings_url, headers=headers, json=rating_payload)

    if ratings_response.status_code == 201:
        status_message = "Rating added successfully!"
    else:
        messagebox.showerror("Error", f"Error adding rating: {ratings_response.status_code}")

    # Close the tkinter window after adding the rating
    window.destroy()

# Create the tkinter window
window = tk.Tk()
window.title("Rate the Episode")

# Create the episode label
episode_label = tk.Label(window, padx=10)
episode_label.pack()

# Create the season label
season_label = tk.Label(window, padx=10)
season_label.pack()

# Create the rating entry
rating_entry = tk.Entry(window)
rating_entry.pack()

# Create a frame to hold the buttons
button_frame = tk.Frame(window)
button_frame.pack()

# Create the submit button
submit_button = tk.Button(button_frame, text="Submit Rating", command=add_rating)
submit_button.pack(side=tk.LEFT, padx=10)

# Bind the Enter key to the add_rating() function
window.bind('<Return>', lambda event: add_rating())

# Create the refresh button
refresh_button = tk.Button(button_frame, text="⟲", command=fetch_latest_history)
refresh_button.pack(side=tk.LEFT, padx=10)

# Set the initial window position
xpos = 785
ypos = 485
window.geometry(f"+{xpos}+{ypos}")

# Fetch the latest history initially
fetch_latest_history()

# Run the tkinter event loop
window.mainloop()
