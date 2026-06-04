# encoding: UTF-8

control 'C-5.4.1.4' do
  title 'Ensure strong password hashing algorithm is configured'
  desc  "
    A cryptographic hash function converts an arbitrary-length input into a fixed length output. Password hashing performs a one-way transformation of a password, turning the password into another string, called the hashed password.

    `ENCRYPT_METHOD` (string) - This defines the system default encryption algorithm for encrypting passwords (if no algorithm are specified on the command line). It can take one of these values:
    - `MD5` - MD5-based algorithm will be used for encrypting password
    - `SHA256` - SHA256-based algorithm will be used for encrypting password
    - `SHA512` - SHA512-based algorithm will be used for encrypting password
    - `BCRYPT` - BCRYPT-based algorithm will be used for encrypting password
    - `YESCRYPT` - YESCRYPT-based algorithm will be used for encrypting password
    - `DES` - DES-based algorithm will be used for encrypting password (default)

    Note:
    - This parameter overrides the deprecated `MD5_CRYPT_ENAB` variable.
    - This parameter will only affect the generation of group passwords.
    - The generation of user passwords is done by PAM and subject to the PAM configuration.
    - It is recommended to set this variable consistently with the PAM configuration.

    The `SHA-512` and `yescrypt` algorithms provide a stronger hash than other algorithms used by Linux for password hash generation. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local group passwords.
  "
  desc  'rationale', "
    A cryptographic hash function converts an arbitrary-length input into a fixed length output. Password hashing performs a one-way transformation of a password, turning the password into another string, called the hashed password.

    `ENCRYPT_METHOD` (string) - This defines the system default encryption algorithm for encrypting passwords (if no algorithm are specified on the command line). It can take one of these values:
    - `MD5` - MD5-based algorithm will be used for encrypting password
    - `SHA256` - SHA256-based algorithm will be used for encrypting password
    - `SHA512` - SHA512-based algorithm will be used for encrypting password
    - `BCRYPT` - BCRYPT-based algorithm will be used for encrypting password
    - `YESCRYPT` - YESCRYPT-based algorithm will be used for encrypting password
    - `DES` - DES-based algorithm will be used for encrypting password (default)

    Note:
    - This parameter overrides the deprecated `MD5_CRYPT_ENAB` variable.
    - This parameter will only affect the generation of group passwords.
    - The generation of user passwords is done by PAM and subject to the PAM configuration.
    - It is recommended to set this variable consistently with the PAM configuration.

    The `SHA-512` and `yescrypt` algorithms provide a stronger hash than other algorithms used by Linux for password hash generation. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local group passwords.
  "
  desc  'check', "
    Run the following command to verify the hashing algorithm is `sha512` or `yescrypt` in `/etc/login.defs`:

    ```
    # grep -Pi -- '^\\h*ENCRYPT_METHOD\\h+(SHA512|yescrypt)\\b' /etc/login.defs
    ```

    _Example output:_

    ```
    ENCRYPT_METHOD SHA512
     - OR -
    ENCRYPT_METHOD  YESCRYPT
    ```
  "
  desc  'fix', "
    Edit `/etc/login.defs` and set the `ENCRYPT_METHOD` to `SHA512` or `YESCRYPT`:

    ```
    ENCRYPT_METHOD ```

    _Example:_

    ```
    ENCRYPT_METHOD YESCRYPT
    ```

    Note: 
    - This only effects local groups' passwords created after updating the file to use `sha512` or `yescrypt`.
    - If it is determined that the password algorithm being used is not `sha512` or `yescrypt`, once it is changed, it is recommended that all group passwords be updated to use the stronger hashing algorithm.
    - It is recommended that the chosen hashing algorithm is consistent across `/etc/login.defs` and the PAM configuration
  "
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'CM-8 a 1']
  tag cci:                   ['CCI-001199', 'CCI-000389']
  tag cis_rid:               '5.4.1.4'
  tag cis_number:            '5.4.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe login_defs do
    its('ENCRYPT_METHOD') { should match(/SHA512|YESCRYPT/i) }
  end
end