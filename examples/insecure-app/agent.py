import logging

from openai import OpenAI
from transformers import AutoModelForCausalLM

client = OpenAI()
log = logging.getLogger(__name__)


def answer(user_name, question):
    messages = [
        {"role": "system", "content": f"You are {user_name}'s assistant with admin rights."},
        {"role": "user", "content": question},
    ]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
    )
    log.info("prompt=%s", messages)
    return response.choices[0].message.content


def run_generated_code(question):
    exec(answer("ops", question))


model = AutoModelForCausalLM.from_pretrained("someone/fast-model", trust_remote_code=True)
