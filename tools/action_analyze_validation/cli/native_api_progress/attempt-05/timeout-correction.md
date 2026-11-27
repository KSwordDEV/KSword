ATTEMPT=05
STATUS=CLIENT_TIMEOUT_BEFORE_PRODUCT_TERMINAL_OBSERVATION

The original attempt-05 request used the fixture's default 15-second response wait. The
client raised queue.Empty after control.api.capture had been issued, so no product terminal
state was observed. This record does not classify that attempt as a product hang or product
failure. The original receipt.json and run.log remain unchanged.

The runner is corrected to pass a 90-second wait for this capture request. startupProgress is
also enabled; its real startup objects are recorded separately from api-capture-progress
frames and are validated only after the response is received.
