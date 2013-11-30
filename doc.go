/*
   package catena implements the catena memory-consuming password
   scrambler.

   The package currently supports the basic scrambling functions,
   with a focus on password hashing. Further releases will see more
   support for the extended parts of Catena, including key derivation,
   server relief, and client-independent updates.

   The tweak can be nil, but it represents an ability to inject
   additional information (include the purpose, hash size, and salt
   length) in the final output.

   The garlic is a parameter that controls the amount of memory
   used.  This implementation restricts the garlic to at most 31.
   The documentation contains performance notes that may be of
   interest to the user. The Catena paper recommends setting the
   initial garlic value to the actual garlic value as a balance
   between memory required and performance.

   The paper recommends a salt length of 16 bytes, but this parameter
   is left up to the user to determine.

   The MatchPassword function properly determines whether a password
   matches the output of the function. This function uses a constant
   time comparison to mitigate timing attacks.
*/
package catena
