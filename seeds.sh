mkdir -p /home/mdimado/Desktop/gsoc/fuzzing/projects/pycups/seeds/fuzz_auth_callback

cd /home/mdimado/Desktop/gsoc/fuzzing/projects/pycups/seeds/fuzz_auth_callback

# Common authentication scenarios
echo -ne "admin\x00password123" > basic_auth.bin
echo -ne "user@domain.com\x00complex_p@ssw0rd!" > email_auth.bin
echo -ne "\x00\x00" > empty_credentials.bin

# Edge cases
echo -ne "very_long_username_that_might_cause_buffer_issues\x00very_long_password_that_might_also_cause_problems" > long_credentials.bin
echo -ne "user\xFF\x00pass\x00word" > special_chars.bin
echo -ne "café\x00pässwörd" > utf8_credentials.bin

# Authentication prompts and methods
echo -ne "Password for admin@printer:\x00GET\x00/admin/conf/" > prompt_data.bin
echo -ne "Enter password:\x00POST\x00/jobs/" > job_auth.bin

# Malformed data
echo -ne "\xFF\xFF\xFF\xFF" > malformed.bin
echo -n "" > empty.bin