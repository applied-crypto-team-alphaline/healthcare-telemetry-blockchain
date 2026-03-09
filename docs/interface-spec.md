# Interface Specification

## Blockchain Registration Record

device_id: string  
public_key: string  
timestamp: integer  
status: active | revoked  
signature: string 


## Telemetry Message Format

device_id: string  
sequence_number: integer  
timestamp: integer  
encrypted_payload: bytes  
authentication_tag: bytes  

## Error Codes

ERR_DEVICE_NOT_REGISTERED  
ERR_PUBLIC_KEY_MISMATCH  
ERR_DEVICE_REVOKED  
ERR_REPLAY_DETECTED  

