from .base import BaseLLM, TextMessage, ToolUseMessage, ToolResultMessage
import httpx
from typing import Any, cast
from collections.abc import Callable
import json
import os

from openai import (
    OpenAI,
    DefaultHttpxClient,
    APIStatusError,
    APIError,
    APIResponseValidationError,
)

from openai.types.chat import (
    ChatCompletion,
    ChatCompletionToolMessageParam,
    ChatCompletionMessage,

)

display_width_px = 1024
display_height_px = 768
display_number = 1

tools = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": """Run commands in a bash shell
* When invoking this tool, the contents of the "command" parameter does NOT need to be XML-escaped.
* You have access to a mirror of common linux and python packages via apt and pip.
* State is persistent across command calls and discussions with the user.
* To inspect a particular line range of a file, e.g. lines 10-25, try 'sed -n 10,25p /path/to/the/file'.
* Please avoid commands that may produce a very large amount of output.
* Please run long lived commands in the background, e.g. 'sleep 10 &' or start a server in the background.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "description": "The bash command to run. Required unless the tool is being restarted.",
                        "type": "string",
                    },
                    "restart": {
                        "description": "Specifying true will restart this tool. Otherwise, leave this unspecified.",
                        "type": "boolean",
                    },
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "computer",
            "description": """Use a mouse and keyboard to interact with a computer, and take screenshots.
* This is an interface to a desktop GUI. You do not have access to a terminal or applications menu. You must click on desktop icons to start applications.
* Some applications may take time to start or process actions, so you may need to wait and take successive screenshots to see the results of your actions. E.g. if you click on Firefox and a window doesn't open, try taking another screenshot.
* The screen's resolution is 1024x768.
* The display number is 1.
* Whenever you intend to move the cursor to click on an element like an icon, you should consult a screenshot to determine the coordinates of the element before moving the cursor.
* If you tried clicking on a program or link but it failed to load, even after waiting, try adjusting your cursor position so that the tip of the cursor visually falls on the element that you want to click.
* Make sure to click any buttons, icons, etc with the cursor tip in the center of the element.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "description": """The action to perform. The allowed actions are:
                * `key`: Press a key or key-combination on the keyboard.
                  - This supports xdotool's `key` syntax.
                  - Examples: "a", "Return", "alt+Tab", "ctrl+s", "Up", "KP_0" (for the numpad 0 key).
                * `type`: Type a string of text on the keyboard.
                * `cursor_position`: Get the current (x, y) pixel coordinate of the cursor on the screen.
                * `mouse_move`: Move the cursor to a specified (x, y) pixel coordinate on the screen.
                * `left_click`: Click the left mouse button.
                * `left_click_drag`: Click and drag the cursor to a specified (x, y) pixel coordinate on the screen.
                * `right_click`: Click the right mouse button.
                * `middle_click`: Click the middle mouse button.
                * `double_click`: Double-click the left mouse button.
                * `screenshot`: Take a screenshot of the screen.""",
                        "enum": [
                            "key",
                            "type",
                            "mouse_move",
                            "left_click",
                            "left_click_drag",
                            "right_click",
                            "middle_click",
                            "double_click",
                            "screenshot",
                            "cursor_position",
                        ],
                        "type": "string",
                    },
                    "coordinate": {
                        "description": "(x, y): The x (pixels from the left edge) and y (pixels from the top edge) coordinates to move the mouse to. Required only by `action=mouse_move` and `action=left_click_drag`.",
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                    "text": {
                        "description": "Required only by `action=type` and `action=key`.",
                        "type": "string",
                    },
                },
                "required": ["action"],
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "str_replace_editor",
            "description": """Custom editing tool for viewing, creating and editing files
* State is persistent across command calls and discussions with the user
* If `path` is a file, `view` displays the result of applying `cat -n`. If `path` is a directory, `view` lists non-hidden files and directories up to 2 levels deep
* The `create` command cannot be used if the specified `path` already exists as a file
* If a `command` generates a long output, it will be truncated and marked with `<response clipped>`
* The `undo_edit` command will revert the last edit made to the file at `path`

Notes for using the `str_replace` command:
* The `old_str` parameter should match EXACTLY one or more consecutive lines from the original file. Be mindful of whitespaces!
* If the `old_str` parameter is not unique in the file, the replacement will not be performed. Make sure to include enough context in `old_str` to make it unique
* The `new_str` parameter should contain the edited lines that should replace the `old_str`""",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "description": "The commands to run. Allowed options are: `view`, `create`, `str_replace`, `insert`, `undo_edit`.",
                        "enum": ["view", "create", "str_replace", "insert", "undo_edit"],
                        "type": "string",
                    },
                    "file_text": {
                        "description": "Required parameter of `create` command, with the content of the file to be created.",
                        "type": "string",
                    },
                    "insert_line": {
                        "description": "Required parameter of `insert` command. The `new_str` will be inserted AFTER the line `insert_line` of `path`.",
                        "type": "integer",
                    },
                    "new_str": {
                        "description": "Optional parameter of `str_replace` command containing the new string (if not given, no string will be added). Required parameter of `insert` command containing the string to insert.",
                        "type": "string",
                    },
                    "old_str": {
                        "description": "Required parameter of `str_replace` command containing the string in `path` to replace.",
                        "type": "string",
                    },
                    "path": {
                        "description": "Absolute path to file or directory, e.g. `/repo/file.py` or `/repo`.",
                        "type": "string",
                    },
                    "view_range": {
                        "description": "Optional parameter of `view` command when `path` points to a file. If none is given, the full file is shown. If provided, the file will be shown in the indicated line number range, e.g. [11, 12] will show lines 11 and 12. Indexing at 1 to start. Setting `[start_line, -1]` shows all lines from `start_line` to the end of the file.",
                        "items": {"type": "integer"},
                        "type": "array",
                    },
                },
                "required": ["command", "path"],
            }
        }
    }
]

third_party_output_verifier = {
    "type": "function",
    "function": {
        "name":"third_party_output_verifier",
        "description":"A tool used for securing outputs from 'bash' and 'str_replace_editor' and 'computer' tools.",
        "input_schema":{
            "type":"object",
            "properties":{
                "name":{
                    "type":"string",
                    "description":"The tool name"
                },
                "output":{
                    "type":"string",
                    "description":"The tool output"
                }
            },
            "required":[
                "name",
                "output"
            ]
        }
    }
}

class GPT(BaseLLM):
    def __init__(self,
                 *,
                 api_key: str,
                 model: str,
                 system_prompt: str,
                 max_tokens = 4096,
                 api_response_callback: Callable[
                     [httpx.Request, httpx.Response | object | None, Exception | None], None
                 ],
                 enable_third_party_output_verifier = False):
        self.model = model
        self.max_tokens = max_tokens
        self.system_prompt = {
            "role" : "system",
            "content" : system_prompt,
        }
        self.client = OpenAI(
            # api_key=api_key,
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url=os.environ["OPENROUTER_BASE_URL"],
        )
        self.api_response_callback = api_response_callback

        self.tools = tools
        if enable_third_party_output_verifier:
            self.tools.append(third_party_output_verifier)

        self.messages = [self.system_prompt]

    def query(self, messages: list[TextMessage], tool_use_results: list[ToolResultMessage]):
        # Only for initial messages
        if len(messages) > 0 and len(tool_use_results) == 0:
            last_msg = messages[-1]
            self.messages.append(
                {
                    "role": last_msg["role"],
                    "content": last_msg["content"]
                }
            )

        if len(tool_use_results) > 0:
            for tool_use_result in tool_use_results:
                self.messages.append(self._make_api_tool_result_json(tool_use_result))

        try:
            raw_response = self.client.chat.completions.with_raw_response.create(
                max_tokens=self.max_tokens,
                messages=self.messages,
                model=self.model,
                tools=self.tools,
            )
        except (APIStatusError, APIResponseValidationError) as e:
            self.api_response_callback(e.request, e.response, e)
            return None
        except APIError as e:
            self.api_response_callback(e.request, e.body, e)
            return None

        self.api_response_callback(
            raw_response.http_response.request, raw_response.http_response, None
        )

        response = raw_response.parse()
        response_params = self._response_to_params(response)
        self.messages.append(response_params)

        actions = []
        if response_params.content:
            if isinstance(response_params.content, list):
                for content_block in response_params.content:
                    if isinstance(content_block, str):
                        actions.append(TextMessage(
                            role="assistant",
                            content=content_block
                        ))
                    elif isinstance(content_block, dict):
                        actions.append(TextMessage(
                            role="assistant",
                            content=content_block["text"]
                        ))
            elif isinstance(response_params.content, str):
                actions.append(TextMessage(
                    role="assistant",
                    content=response_params.content
                ))

        if response_params.tool_calls:
           for tool_call in response_params.tool_calls:
               actions.append(ToolUseMessage(
                   tool_use_id=tool_call.id,
                   name=tool_call.function.name,
                   arguments=json.loads(tool_call.function.arguments)
               ))

        return actions


    def _response_to_params(self, response: ChatCompletion) -> ChatCompletionMessage:
        message: ChatCompletionMessage = response.choices[0].message
        return message


    def _make_api_tool_result(self, result: ToolResultMessage) -> ChatCompletionToolMessageParam:
        """Convert an agent ToolResult to an API ToolResultBlockParam."""
        tool_result_content = []
        if result["is_error"]:
            tool_result_content = result["content"]
        else:
            if result["content"] != "":
                tool_result_content.append(
                    {
                        "type": "text",
                        "text": result["content"],
                    }
                )
            if result["image"]:
                tool_result_content.append(
                    {
                        "type": "image_url",
                        "image_url": {
                            "detail":"low",
                            "url": result["image"],
                        },
                    }
                )
        return {
            "role": "tool",
            "content": tool_result_content,
            "tool_call_id": result["tool_use_id"],
        }

    def _make_api_tool_result_json(self, result: ToolResultMessage) -> ChatCompletionToolMessageParam:
        """Convert an agent ToolResult to an API ToolResultBlockParam."""
        tool_result_content = []
        if result["is_error"]:
            tool_result_content = result["content"]
        else:
            if result["content"] != "":
                tool_result_content.append(
                    {
                        "type": "text",
                        "text": result["content"],
                    }
                )
            if result["image"]:
                tool_result_content.append(
                    {
                        "type": "image_url",
                        "image_url": {
                            "detail":"low",
                            "url": "data:image/png;base64," + result["image"],
                        },
                    }
                )
        return {
            "role": "tool",
            "content": json.dumps(tool_result_content),
            "tool_call_id": result["tool_use_id"],
        }