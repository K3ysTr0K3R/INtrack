import random

def load_user_agents():
    with open('lib/headers/user_agents.txt' ,'r', encoding="utf-8") as file:
        return [line.strip() for line in file]

def user_agents():
    user_agent_list = load_user_agents()
    user_agent = random.choice(user_agent_list)
    sanitized_user_agent = user_agent.encode('ascii', errors='ignore').decode('ascii')
    return sanitized_user_agent
