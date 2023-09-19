%%  -*- erlang-mode -*-
%%  Copyright Avassa Systems AB
%%
%%  The contents of this file is subject to copyright and may only be used
%%  in accordance with the license received together with this file.
%%
%%  File:    parsec.hrl
%%  Author:  Johan Bevemyr
%%  Created: Tue Sep 19 10:31:21 2023

-ifndef(PARSEC_HRL).
-define(PARSEC_HRL, true).

-define(stack(), try throw(1) catch _:_:Stack -> Stack end).

-define(iof(F), io:format(standard_error, "~p: ~s:~p: " ++ F,
                          [node(),?MODULE,?LINE])).
-define(iof(F,A), io:format(standard_error, "~p: ~s:~p: " ++ F,
                            [node(),?MODULE,?LINE|A])).
-define(iof_bt(F,A), io:format(standard_error, "~p: ~s:~p: ~s ~p\n",
                               [node(), ?MODULE,?LINE, io_lib:format(F,A),
                                ?stack()])).


-define(liof(F),      ?iof(F)).
-define(liof(F,A),    ?iof(F,A)).
-define(liof_bt(F),   ?iof_bt(F)).
-define(liof_bt(F,A), ?iof_bt(F,A)).

-define(io2b, iolist_to_binary).
-define(i2l,  integer_to_list).
-define(l2i,  list_to_integer).
-define(b2l,  binary_to_list).
-define(l2b,  list_to_binary).
-define(t2b,  term_to_binary).
-define(b2t,  binary_to_term).
-define(a2l,  atom_to_list).
-define(l2a,  list_to_atom).
-define(l2ea, list_to_existing_atom).
-define(b2a,  binary_to_atom).
-define(b2ea, binary_to_existing_atom).
-define(a2b,  atom_to_binary).
-define(l2t,  list_to_tuple).
-define(t2l,  tuple_to_list).
-define(i2b,  integer_to_binary).
-define(b2i,  binary_to_integer).
-define(b2f,  binary_to_float).

-define(s2l(X), if is_binary(X) -> ?b2l(X);
                   is_atom(X)   -> ?a2l(X);
                   is_list(X)   -> X
                end).

-define(s2b(X), if is_binary(X) -> X;
                   is_atom(X)   -> ?a2b(X, utf8);
                   is_list(X)   -> ?l2b(X)
                end).

-endif.
