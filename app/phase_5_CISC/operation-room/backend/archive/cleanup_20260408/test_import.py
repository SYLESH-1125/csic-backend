import sys, os
sys.path.insert(0, r"c:\CISC\operation-room\backend")
try:
    from operation_room.services.correlation_agent import chat_with_agent
    print("Successfully imported!")
except Exception as e:
    import traceback
    traceback.print_exc()
