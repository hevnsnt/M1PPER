/* See COPYING.txt for license details. */

/*
*
* m1_games.c
*
* The shared game/app utility helpers (`game_poll_button`, `game_rand_*`)
* moved to m1_input.c and m1_rand.c so that non-game apps could use them
* without depending on a "games" header. The legacy game_* identifiers
* are now forwarding inline functions defined in m1_games.h.
*
* M1 Project
*
*/

/* Intentionally empty — kept so that existing CMakeLists.txt source lists
 * remain valid without an immediate edit. Future cleanup can drop this
 * file and remove the entry. */
