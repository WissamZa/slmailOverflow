

# The script work in kali to help for slmail buffer overflow
you need to change the permission for the script to execute by chmod:<br>
```sudo chmod +x ./slmail-overflow.py```

-f :  check if there an overflow or not and in which byte     
-p :  check the address where EIP overwriten<br>
-b :  check if our work is correct by see EIP fill with 42424242 or not<br>
-d :  check for bad charcters<br>
-s :  for upload the shell but you need to create the shell first and put the shull code in the script in shull method 
      see the instration in the comment in the script<br>

example:
```./slmail-overflow.py -f 192.168.56.10```

