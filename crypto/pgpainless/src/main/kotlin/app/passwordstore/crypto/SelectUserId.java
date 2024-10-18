// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

//package org.pgpainless.util.selection.userid;
package app.passwordstore.crypto;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.openpgp.PGPKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.info.KeyRingInfo;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Filter for selecting user-ids from keys and from lists.
 */
public abstract class SelectUserId {

    /**
     * Return true, if the given user-id is accepted by this particular filter, false otherwise.
     *
     * @param userId user-id
     * @return acceptance of the filter
     */
    protected abstract boolean accept(@Nonnull String userId);

    /**
     * Select all currently valid user-ids of the given key ring.
     *
     * @param keyRing public or secret key ring
     * @return valid user-ids
     */
    @Nonnull
    public List<String> selectUserIds(@Nonnull PGPKeyRing keyRing) {
        List<String> userIds = PGPainless.inspectKeyRing(keyRing).getValidUserIds();
        return selectUserIds(userIds);
    }

    /**
     * Select all acceptable (see {@link #accept(String)}) from the given list of user-ids.
     *
     * @param userIds list of user-ids
     * @return sub-list of acceptable user-ids
     */
    @Nonnull
    public List<String> selectUserIds(@Nonnull List<String> userIds) {
        List<String> selected = new ArrayList<>();
        for (String userId : userIds) {
            if (accept(userId)) {
                selected.add(userId);
            }
        }
        return selected;
    }

    /**
     * Return the first valid, acceptable user-id from the given public or secret key ring.
     *
     * @param keyRing public or secret key ring
     * @return first matching valid user-id or null
     */
    @Nullable
    public String firstMatch(@Nullable PGPKeyRing keyRing) {
        return firstMatch(selectUserIds(keyRing));
    }

    /**
     * Return the first valid, acceptable user-id from the list of user-ids.
     *
     * @param userIds list of user-ids
     * @return first matching valid user-id or null
     */
    @Nullable
    public String firstMatch(@Nonnull List<String> userIds) {
        for (String userId : userIds) {
            if (accept(userId)) {
                return userId;
            }
        }
        return null;
    }

    /**
     * Filter that filters for user-ids which contain the given <pre>query</pre> as a substring.
     *
     * @param query query
     * @return filter
     */
    @Nonnull
    public static SelectUserId containsSubstring(@Nonnull CharSequence query) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return userId.contains(query.toString());
            }
        };
    }

    /**
     * Filter that filters for user-ids which match the given <pre>query</pre> exactly.
     *
     * @param query query
     * @return filter
     */
    @Nonnull
    public static SelectUserId exactMatch(@Nonnull CharSequence query) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return userId.equals(query.toString());
            }
        };
    }

    /**
     * Filter that filters for user-ids which start with the given <pre>substring</pre>.
     *
     * @param substring substring
     * @return filter
     */
    @Nonnull
    public static SelectUserId startsWith(@Nonnull CharSequence substring) {
        String string = substring.toString();
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return userId.startsWith(string);
            }
        };
    }

    /**
     * Filter that filters for user-ids which contain the given <pre>email</pre> address.
     * Note: This only accepts user-ids which properly have the email address surrounded by angle brackets.
     *
     * The argument <pre>email</pre> can both be a plain email address (<pre>"foo@bar.baz"</pre>),
     * or surrounded by angle brackets ({@code <pre>"<foo@bar.baz>"</pre>}), the result of the filter will be the same.
     *
     * @param email email address
     * @return filter
     */
    @Nonnull
    public static SelectUserId containsEmailAddress(@Nonnull CharSequence email) {
        String string = email.toString();
        return containsSubstring(string.matches("^<.+>$") ? string : '<' + string + '>');
    }

    /**
     * Filter that filters for valid user-ids on the given <pre>keyRing</pre> only.
     *
     * @param keyRing public / secret keys
     * @return filter
     */
    @Nonnull
    public static SelectUserId validUserId(@Nonnull PGPKeyRing keyRing) {
        final KeyRingInfo info = PGPainless.inspectKeyRing(keyRing);

        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return info.isUserIdValid(userId);
            }
        };
    }

    /**
     * Filter that filters for user-ids which pass all the given <pre>filters</pre>.
     *
     * @param filters filters
     * @return filter
     */
    @Nonnull
    public static SelectUserId and(@Nonnull SelectUserId... filters) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                boolean accept = true;
                for (SelectUserId filter : filters) {
                    accept &= filter.accept(userId);
                }
                return accept;
            }
        };
    }

    /**
     * Filter that filters for user-ids which pass at least one of the given <pre>filters</pre>.
     *
     * @param filters filters
     * @return filter
     */
    @Nonnull
    public static SelectUserId or(@Nonnull SelectUserId... filters) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                boolean accept = false;
                for (SelectUserId filter : filters) {
                    accept |= filter.accept(userId);
                }
                return accept;
            }
        };
    }

    /**
     * Filter that inverts the result of the given <pre>filter</pre>.
     *
     * @param filter filter
     * @return inverting filter
     */
    @Nonnull
    public static SelectUserId not(@Nonnull SelectUserId filter) {
        return new SelectUserId() {
            @Override
            protected boolean accept(String userId) {
                return !filter.accept(userId);
            }
        };
    }

    /**
     * Filter that selects user-ids by the given <pre>email</pre> address.
     * It returns user-ids which either contain the given <pre>email</pre> address as angle-bracketed string,
     * or which equal the given <pre>email</pre> string exactly.
     *
     * @param email email
     * @return filter
     */
    @Nonnull
    public static SelectUserId byEmail(@Nonnull CharSequence email) {
        return SelectUserId.or(
                SelectUserId.exactMatch(email),
                SelectUserId.containsEmailAddress(email)
        );
    }
}
