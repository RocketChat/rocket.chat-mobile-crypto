export const RSA_FIXED_PRIVATE_JWK = JSON.stringify({
  kty: 'RSA',
  alg: 'RSA-OAEP-256',
  ext: true,
  key_ops: ['decrypt'],
  n:
    'pylHgGGx_ZNDxaJsVzIqvdu4yHC0J_BRdKUwN31ZzkZ-vUuQC1SFKFbCOtM9mmBJ' +
    'T_l33aHuJAp3yRlhW_uqR39zKMMECUG0Q7xQckZ62sqKfEQtNNm2OI8aCYg_SExL' +
    'W-kjLXjWQGkrrmomcZ6ndsHGImUBFoRf54mDUG8GAkHz3BCMQ1_rwOhEDrOmrDJt' +
    'HVteKrQQvcTIWNXkgFSFxGsSsTKnnZZAxykXi25SwEXmwmEHQrAnEXBvqP5998oD' +
    'Oz1_HFnu9U29RVBqjwBgVii4J3WPzS5HsKxhPrbB7mk4gw7YqWi0eXX3OUTWyqlQ' +
    'nTh6339eobtEyq8_QACztQ',
  e: 'AQAB',
  d:
    'C0pX-H1gwsJQGQiz7Z3HUkSFchBesrXiIpFHtO_EAZE0XT-9zm4aglN90fBToFox' +
    'iXPNm0wlJA0K8yvCLi7M3QBoPFATtTZZYRvWiSlmgeGdQfBu5ztvOdm8hflMYOs6' +
    'Sc5w4FDhk78mwqSLzS_MmtJSuh79WFJ_kclxc5zUGJHUtj7LJN39XVoo7QHNsR-j' +
    'irmEjKNhSfcua7GhkZZC_u21jIvse9cwJBGQHazTWesPXM6n37pqVMRqR8uQ-q-Z' +
    'fesfiJZENSVkKYkd3yRIHRFkgN-sKSEgKcyuE71Yj6wDjA9HZQVSTdiiqsrwUFeo' +
    '3fEib9fBgPXMRBc51X49Xw',
  p:
    '5ki-jB9ldtswd0vhA_GW_wkiDivq4w_8AFVhTHBoCklbQvaovMGOkSgwazVtT-Qa' +
    'Yda6r5jMMRK5_6vBh3vVsZhTIz64OdKIwDZdJCfv6WNw_UJgnQ12i-WGNBkkkIBr' +
    'cPVsqmxa63xKduwRQaJ1hJkFGdW-vA9YPAHFtppXtcM',
  q:
    'udQBu-qoWTuvoRZKzVs_3re3OqVK5ze4C4qUlvNkijedtQ15Ow8sf4SAMgEblYpm' +
    'B84uu3ZJSCML-G9pC4Vgbafag-c-XIo6WAF85StmcsON2r7my4ya8ckTgNYkJb8K' +
    'Z0j-xlLCASK1Fhgw4yEXINovQD9wksy5MXK9pHs0wSc',
  dp:
    'KYeW7Zg_6SZwYCNMCjUIgSf5f0rGSnq4fKrpKCrhaHGARtxK4_eYKW9xA_SXqR--' +
    '7kQWWNKaiIMTDhvAhBl-GVAaNjH6cVsZlGh5darKJnHrj5Dn8YrbBTG4eS7LnE-8' +
    'kJuCJF30K6G3oCjEl-yfevFJrTYR9sJhrDi5mkvNY5c',
  dq:
    'ZWtH5v-TEeB5YjmAacO7gBpUbjV4Q-ktEV946Um9PZJNCFtqJsmJR69RJ_lizKLU' +
    'PL5S0w0jwbMe_WAQvLD2h-JsaED00BzA6vck6w5cw5Xm_dPisoTyq7NKaa513AP_' +
    '8Y7tPeA88dG3c2-QfuW4cb2ivDXjgrso98vfpL15dVE',
  qi:
    'afRV_ChXGrtlyUAHJ_-fFEpa5EWrVXXTuvNQtR41eV6KKTX9h80VP2BOlKjpQUh_' +
    'yChGdxIRLKy5e1bZzbLySTezxS0kBerWY4DQX7fw7gOYJrlNgfDo0zNe92_wfQyU' +
    'IaENzWL2H4KGwq8HwkaGebRc3cngoS2ckHzmRez8wgE',
});

export const RSA_FIXED_PUBLIC_JWK = JSON.stringify({
  kty: 'RSA',
  alg: 'RSA-OAEP-256',
  ext: true,
  key_ops: ['encrypt'],
  n:
    'pylHgGGx_ZNDxaJsVzIqvdu4yHC0J_BRdKUwN31ZzkZ-vUuQC1SFKFbCOtM9mmBJ' +
    'T_l33aHuJAp3yRlhW_uqR39zKMMECUG0Q7xQckZ62sqKfEQtNNm2OI8aCYg_SExL' +
    'W-kjLXjWQGkrrmomcZ6ndsHGImUBFoRf54mDUG8GAkHz3BCMQ1_rwOhEDrOmrDJt' +
    'HVteKrQQvcTIWNXkgFSFxGsSsTKnnZZAxykXi25SwEXmwmEHQrAnEXBvqP5998oD' +
    'Oz1_HFnu9U29RVBqjwBgVii4J3WPzS5HsKxhPrbB7mk4gw7YqWi0eXX3OUTWyqlQ' +
    'nTh6339eobtEyq8_QACztQ',
  e: 'AQAB',
});

export const RSA_FIXED_PLAINTEXT = 'Hello RSA fixed vector!';
export const RSA_FIXED_SIGN_MESSAGE = 'Hello RSA signature fixed vector!';
export const RSA_UNICODE_PLAINTEXT = 'Rocket.Chat 🔐 — olá';

export const RSA_FIXED_OAEP_CIPHERTEXT =
  'i08WpnMEqWx2wLI85uir06hnBpUgMM/zO1y/XWgue/tIz6Nb28MFTBuDPMshhpoz' +
  'WM8uhYhfcnYAPwAmKiN5Mp8uFYKO2f0kpSs7GYopR7D284NX+ar67LLxXgRdDhXb' +
  'mo5msDqSCmrhN1MTMVI2GGr/RStdRyODmHiRAqw0+6OM1431GvNm2MOPh+imTEwgu' +
  'Si/tqiWvRDP4n9A9Kk+tBrhJLfHjMMY5ig1NuvzV35KM96hw6R6VpcWVX3cNbnxW' +
  'bytRsygp7oswA83PZtAvLH8wIAqLDBHoQTHNg0TNWbfR6WxoSecTh7W/4iB8XUeJ' +
  '4mwT/KgnRz6yIVQ0iLgnw==';

export const RSA_UNICODE_OAEP_CIPHERTEXT =
  'UaKbHdTYmbM/+U9emxDf5Wo6PKO0xG9aSeR2QYxeBQVz5zF81GoximcX3FpApwsP' +
  'W7m7SLnQX6mJFbBhbsbGE3TyQGEPuVLt2+0xCOw7rjtYWbggkcX6njvIZI9MD6tb' +
  'VUc1tzhx3jlO4fOe8PDQjA+VYK4mIrRVTRFNWLf1pZLP4MBLU2fq1uFkFC8eomcM' +
  'wt539cNtcuMHo0mV5ayMg8/UI7AnUZhVp/KUC4h8bbGiokLlyOQGF6DqvrO3lhIv' +
  'IfPo/z5mfIF8EVdRck/lsFUD4HFZ2DzmTbZRy/hWHudrdY11Or0bxwxNK6V6+KlR' +
  'J4wr3mt+RHe5zSaw9DnSRg==';

export const RSA_FIXED_SIGNATURE =
  'lySFWshaUVSbp+U1m+dq1wW4VuHBX1jE30L4gJywhjvfB4jMf2WrTMdYbdMnvXgj' +
  'E4kGJ3Lkcu5C6isOUHZMMIYDdL8DRW6GNTWj5ChwQXLQ6TV0NYkOmGqrEkWxztk6' +
  '/lu/SWogTuKiq7iVpbAtjfyFTY6GWeyqIw0AOoFfDKQSezeF6ubRkKEDLc42v+pX' +
  'FTRxWMJTMXX6+Xz5PiDV+ApXO4ExDtsgW1gqwNUTeY7y/A+2XIxllZTVj4LB7twa' +
  'K5DirX0GIvUD5VomiHiy8dGGQc3m8FZa6c5te78FC7JCe4GRLHKNdH1hzEggTH3S' +
  'MDHrlJnNqFiE2bQenbHKEg==';
