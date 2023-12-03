import requests

# Specify your Trakt.tv API credentials
client_id = '76a97838e5a04002f019218b1003f69419e5f72b57ba20f2aed9c4636cf83122'
client_secret = '34cbc718b56e77e79c235287e631ef1fac463375347369e291d79142d8fb1d8b'
access_token = 'e28b728b399085fdba6070071ad8100929cde819f4e99912d34eaf116954003c'

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
    'action': 'scrobble'
}

# Send the GET request to retrieve the history
history_response = requests.get(history_url, headers=headers, params=history_params)

if history_response.status_code == 200:
    # Extract the latest watched episode from the response
    latest_episode = history_response.json()[0]

    # Access the relevant information (e.g., title, season, episode number)
    episode_title = latest_episode['episode']['title']
    season_number = latest_episode['episode']['season']
    episode_number = latest_episode['episode']['number']

    # Print the details of the latest watched episode
    print(f"Latest Episode Watched: {episode_title}")
    print(f"Season: {season_number}  Episode: {episode_number}")

    # Prompt the user to input a rating
    rating = input("Enter the rating for the episode: ")

    # Create the payload with the episode rating data
    rating_payload = {
        "episodes": [
            {
                "rating": rating,
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
        print("Rating added successfully!")
    else:
        print("Error adding rating:", ratings_response.status_code)
else:
    print("Error retrieving history:", history_response.status_code)
