% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(aegis).
-include("aegis.hrl").
-include_lib("fabric/include/fabric2.hrl").

%% TODO - get from key manager
-define(ROOT_KEY, <<1:256>>).

-define(WRAPPED_KEY, {?DB_AEGIS, 1}).


-export([
    create/2,
    open/2,

    decrypt/2,
    encrypt/2,
    wrap_fold_fun/2
]).

create(#{} = Db, Options) ->
    #{
        tx := Tx,
        db_prefix := DbPrefix
    } = Db,

    % Generate new key
    DbKey = crypto:strong_rand_bytes(32),

    % protect it with root key
    WrappedKey = aegis_keywrap:key_wrap(?ROOT_KEY, DbKey),

    % And store it
    FDBKey = erlfdb_tuple:pack(?WRAPPED_KEY, DbPrefix),
    ok = erlfdb:set(Tx, FDBKey, WrappedKey),

    Db#{
        aegis => DbKey
    }.


open(#{} = Db, Options) ->
    #{
        tx := Tx,
        db_prefix := DbPrefix
    } = Db,

    % Fetch wrapped key
    FDBKey = erlfdb_tuple:pack(?WRAPPED_KEY, DbPrefix),
    WrappedKey = erlfdb:wait(erlfdb:get(Tx, FDBKey)),

    % Unwrap it
    DbKey = aegis_keywrap:key_unwrap(?ROOT_KEY, WrappedKey),

    Db#{
        aegis => DbKey
    }.


encrypt(#{} = _Db, <<>>) ->
    <<>>;

encrypt(#{} = Db, Value) when is_binary(Value) ->
    #{
        aegis := DbKey
    } = Db,

    Key = crypto:strong_rand_bytes(32),
    <<WrappedKey:320>> = aegis_keywrap:key_wrap(DbKey, Key),

    {CipherText, <<CipherTag:128>>} =
        ?aes_gcm_encrypt(
           Key,
           <<0:96>>,
           <<>>,
           Value),
    <<1:8, WrappedKey:320, CipherTag:128, CipherText/binary>>.


decrypt(#{} = Db, Rows) when is_list(Rows) ->
    lists:map(fun({Key, Value}) ->
        {Key, decrypt(Db, Value)}
    end, Rows);

decrypt(#{} = _Db, <<>>) ->
    <<>>;

decrypt(#{} = Db, Value) when is_binary(Value) ->
    #{
        aegis := DbKey
    } = Db,

    case Value of
        <<1:8, WrappedKey:320, CipherTag:128, CipherText/binary>> ->
            case aegis_keywrap:key_unwrap(DbKey, <<WrappedKey:320>>) of
                fail ->
                    erlang:error(decryption_failed);
                Key ->
                    Decrypted =
                    ?aes_gcm_decrypt(
                        Key,
                        <<0:96>>,
                        <<>>,
                        CipherText,
                        <<CipherTag:128>>),
                    if Decrypted /= error -> Decrypted; true ->
                        erlang:error(decryption_failed)
                    end
            end;
        _ ->
            erlang:error(not_ciphertext)
    end.


wrap_fold_fun(Db, Fun) when is_function(Fun, 2) ->
    fun({Key, Value}, Acc) ->
        Fun({Key, decrypt(Db, Value)}, Acc)
    end.
