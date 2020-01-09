%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emqx_auth_ldap).

-include("emqx_auth_ldap.hrl").

-include_lib("emqx/include/emqx.hrl").
-include_lib("eldap/include/eldap.hrl").
-include_lib("emqx/include/logger.hrl").

-import(proplists, [get_value/2]).

-import(emqx_auth_ldap_cli, [search/2]).

-export([ register_metrics/0
        , check/3
        , description/0
        , replace_vars/2
        , compile_filters/2
        ]).

-spec(register_metrics() -> ok).
register_metrics() ->
    lists:foreach(fun emqx_metrics:new/1, ?AUTH_METRICS).

check(ClientInfo = #{username := Username, password := Password}, AuthResult,
      State = #{password_attr := PasswdAttr}) ->
    CheckResult = case lookup_user(Username, Password, State) of
                      undefined -> {error, not_found};
                      {error, Error} -> {error, Error};
                      Attributes ->
                          case get_value(PasswdAttr, Attributes) of
                              undefined ->
                                  logger:error("LDAP Search State: ~p, uid: ~p, result:~p",
                                               [State, Username, Attributes]),
                                  {error, not_found};
                              [Passhash1] ->
                                  format_password(Passhash1, Password, ClientInfo)
                          end
                  end,
    case CheckResult of
        ok ->
            ok = emqx_metrics:inc(?AUTH_METRICS(success)),
            {stop, AuthResult#{auth_result => success, anonymous => false}};
        {error, not_found} ->
            emqx_metrics:inc(?AUTH_METRICS(ignore));
        {error, ResultCode} ->
            ok = emqx_metrics:inc(?AUTH_METRICS(failure)),
            ?LOG(error, "[LDAP] Auth from ldap failed: ~p", [ResultCode]),
            {stop, AuthResult#{auth_result => ResultCode, anonymous => false}}
    end.

lookup_user(Username, Password, #{username_attr := UidAttr,
                                  match_objectclass := ObjectClass,
                                  device_dn := DeviceDn,
                                  bind_as_user := BindAsUserRequired,
                                  custom_base_dn := CustomBaseDN} = Config) ->

    Filters = maps:get(filters, Config, []),

    ReplaceRules = [{"${username_attr}", UidAttr},
                    {"${user}", binary_to_list(Username)},
                    {"${device_dn}", DeviceDn}],
    PasswordString = binary_to_list(Password),

    %% Here the original filter could be appended to the list of filters, like
    %% ["and",{"objectClass", ObjectClass}]
    %% ==> "|(&((objectClass=Class)(uiAttr=someAttr))(someKey=someValue))"

    SubFilters =
        lists:map(fun({K, V}) ->
                          {replace_vars(K, ReplaceRules), replace_vars(V, ReplaceRules)};
                     (Op) ->
                          Op
                  end, Filters),

    Filter =
        case SubFilters of
            [] -> eldap2:equalityMatch("objectClass", ObjectClass);
            _List -> compile_filters(SubFilters, [])
        end,

    %% auth.ldap.custom_base_dn = "${username_attr}=${user},${device_dn}"
    BaseDN = replace_vars(CustomBaseDN, ReplaceRules),

    case {search(BaseDN, Filter), BindAsUserRequired} of
        {{error, noSuchObject}, _} ->
            undefined;
        {{ok, #eldap_search_result{entries = [Entry]}}, true} ->
            Attributes = Entry#eldap_entry.attributes,
            case get_value("isEnabled", Attributes) of
                undefined ->
                    case emqx_auth_ldap_cli:post_bind(Entry#eldap_entry.object_name, PasswordString) of
                        ok ->
                            Attributes;
                        {error, Reason} ->
                            {error, Reason}
                    end;
                [Val] ->
                    case list_to_atom(string:to_lower(Val)) of
                        true ->
                            case emqx_auth_ldap_cli:post_bind(Entry#eldap_entry.object_name, PasswordString) of
                                ok ->
                                    Attributes;
                                {error, Reason} ->
                                    {error, Reason}
                            end;
                        false ->
                            {error, username_disabled}
                    end
            end;

        {{ok, #eldap_search_result{entries = [Entry]}}, false} ->
            Attributes = Entry#eldap_entry.attributes,
            case get_value("isEnabled", Attributes) of
                undefined ->
                    Attributes;
                [Val] ->
                    case list_to_atom(string:to_lower(Val)) of
                        true -> Attributes;
                        false -> {error, username_disabled}
                    end
            end;
        {error, Error} ->
            ?LOG(error, "[LDAP] Search dn: ~p, filter: ~p, fail:~p", [DeviceDn, Filter, Error]),
            {error, username_or_password_error}
    end.

check_pass(Password, Password, _ClientInfo) -> ok;
check_pass(_, _, _) -> {error, bad_username_or_password}.

format_password(Passhash, Password, ClientInfo) ->
    case do_format_password(Passhash, Password) of
        {error, Error2} ->
            {error, Error2};
        {Passhash1, Password1} ->
            check_pass(Passhash1, Password1, ClientInfo)
    end.

do_format_password(Passhash, Password) ->
    Base64PasshashHandler =
    handle_passhash(fun(HashType, Passhash1, Password1) ->
                            Passhash2 = binary_to_list(base64:decode(Passhash1)),
                            resolve_passhash(HashType, Passhash2, Password1)
                    end,
                    fun(_Passhash, _Password) ->
                            {error, password_error}
                    end),
    PasshashHandler = handle_passhash(fun resolve_passhash/3, Base64PasshashHandler),
    PasshashHandler(Passhash, Password).

resolve_passhash(HashType, Passhash, Password) ->
    [_, Passhash1] = string:tokens(Passhash, "}"),
    do_resolve(HashType, Passhash1, Password).

handle_passhash(HandleMatch, HandleNoMatch) ->
    fun(Passhash, Password) ->
            case re:run(Passhash, "(?<={)[^{}]+(?=})", [{capture, all, list}, global]) of
                {match, [[HashType]]} ->
                    HandleMatch(list_to_atom(string:to_lower(HashType)), Passhash, Password);
                _ ->
                    HandleNoMatch(Passhash, Password)
            end
    end.

do_resolve(ssha, Passhash, Password) ->
    D64 = base64:decode(Passhash),
    {HashedData, Salt} = lists:split(20, binary_to_list(D64)),
    NewHash = crypto:hash(sha, <<Password/binary, (list_to_binary(Salt))/binary>>),
    {list_to_binary(HashedData), NewHash};
do_resolve(HashType, Passhash, Password) ->
    Password1 = base64:encode(crypto:hash(HashType, Password)),
    {list_to_binary(Passhash), Password1}.

description() -> "LDAP Authentication Plugin".

compile_filters([{Key, Value}], []) ->
    compile_equal(Key, Value);
compile_filters([{K1, V1}, "and", {K2, V2} | Rest], []) ->
    compile_filters(
      Rest,
      eldap2:'and'(compile_equal(K1, V1),
                   compile_equal(K2, V2)));
compile_filters([{K1, V1}, "or", {K2, V2} | Rest], []) ->
    compile_filters(
      Rest,
      eldap2:'or'(compile_equal(K1, V1),
                  compile_equal(K2, V2)));
compile_filters(["and", {K, V} | Rest], PartialFilter) ->
    compile_filters(
      Rest,
      eldap2:'and'(PartialFilter,
                   compile_equal(K, V)));
compile_filters(["or", {K, V} | Rest], PartialFilter) ->
    compile_filters(
      Rest,
      eldap2:'or'(PartialFilter,
                  compile_equal(K, V)));
compile_filters([], Filter) ->
    Filter.

compile_equal(Key, Value) ->
    eldap2:equalityMatch(Key, Value).

replace_vars(CustomBaseDN, ReplaceRules) ->
    lists:foldl(fun({Pattern, Substitute}, DN) ->
                        lists:flatten(string:replace(DN, Pattern, Substitute))
                end, CustomBaseDN, ReplaceRules).
