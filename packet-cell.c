/* packet-cell.c
 * Routines for cell (part of Tor) dissection
 * Copyright 2016, Lukas Schwaighofer <schwaigh@in.tum.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#if 0
/* Include only as needed */
#include <stdlib.h>
#include <string.h>
#endif
#include <stdio.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-ssl.h>

#define SSL_CELL_DEFAULT_PORT_RANGE "5000"
#define CELL_MAX_INFO_COLUMN_LEN 100

static dissector_handle_t cell_handle;

/* Forward declaration that is needed below if using the
 * proto_reg_handoff_cell function as a callback for when protocol
 * preferences get changed. */
void proto_reg_handoff_cell(void);
void proto_register_cell(void);

/* Initialize the protocol and registered fields */
static int proto_cell = -1;
static int hf_cell_circid = -1;
static int hf_cell_command = -1;
static const value_string cell_commands [] = {
    /* fixed length cell commands */
    {   0, "PADDING" },
    {   1, "CREATE" },
    {   2, "CREATED" },
    {   3, "RELAY" },
    {   4, "DESTROY" },
    {   5, "CREATE_FAST" },
    {   6, "CREATED_FAST" },
    {   7, "VERSIONS" }, /* versions is variable length */
    {   8, "NETINFO" },
    {   9, "RELAY_EARLY" },
    {  10, "CREATE2" },
    {  11, "CREATED2" },
    /* all variable length cell commands below */
    { 128, "VPADDING" },
    { 129, "CERTS" },
    { 130, "AUTH_CHALLENGE" },
    { 131, "AUTHENTICATE" },
    { 132, "AUTHORIZE" },
    /* end of array, required */
    {   0, NULL }
};
static int hf_cell_length = -1;
static int hf_cell_payload = -1;

/* Global port range (ssl) */
static range_t *global_cell_ssl_range = NULL;

/* Initialize the subtree pointers */
static gint ett_cell = -1;

/* minimum needed for variable length is CircID (>=2), command (=1), length
 * (=2)  and 2 octets payload; fixed length have even more */
#define CELL_MIN_LENGTH 7
/* we assume protocol version >=4, so fixed length is 514 for us */
#define CELL_FIXED_LENGTH 514

/* Helper function to assemble the info column */
static void
add_cell_info(char *buffer, int *idx, guint8 cell_command) {
    const char *info = val_to_str(cell_command, cell_commands,
            "Unknown cmd(%d)");
    int available = CELL_MAX_INFO_COLUMN_LEN - *idx;
    int copied;
    if (*idx == 0)
        copied = snprintf(buffer, available, "Cell protocol: %s", info);
    else
        copied = snprintf(buffer + *idx, available, " | %s", info);
    if (copied > available)
        *idx += available;
    else
        *idx += copied;
}

/* Code to actually dissect the packets */
static int
dissect_cell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *cell_tree;
    /* Other misc. local variables. */
    guint offset = 0;
    guint reported_length, available, required_length, payload_length;
    guint8 cell_command;
    char info_column[CELL_MAX_INFO_COLUMN_LEN + 1];
    int info_column_idx = 0;
    info_column[CELL_MAX_INFO_COLUMN_LEN] = 0;

    /*** HEURISTICS ***/

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < CELL_MIN_LENGTH)
        return 0;

    /* TODO: more heuristics, return 0 if we think it's not cell */

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'PROTOABBREV',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of PROTOABBREV */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "cell");

    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);

    /* col_set_str(pinfo->cinfo, COL_INFO, "Cell protocol"); */

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    reported_length = tvb_reported_length(tvb);
    while(offset < reported_length) {
        available = tvb_reported_length_remaining(tvb, offset);
        /* minimum length to be a version packet */
        if (available < CELL_MIN_LENGTH) {
            /* we are running out of data, ask for more (unkown how much) */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            col_add_str(pinfo->cinfo, COL_INFO, info_column);
            return reported_length;

        }
        /* check for version packet */
        if (tvb_get_guint8(tvb, offset) == 0 &&
                tvb_get_guint8(tvb, offset + 1) == 0 &&
                tvb_get_guint8(tvb, offset + 2) == 7) {
            /* this is (most likely) a version packet; could also be the
             * circuit ID if we're very unlucky; TODO: is it possible to match
             * for beginning of conversation using the tvb to avoid this? */
            payload_length = tvb_get_ntohs(tvb, offset + 3);
            required_length = payload_length + 5;
            if (available < required_length) {
                /* we are running out of data, ask for more */
                pinfo->desegment_offset = offset;
                /* TODO: used correctly? */
                pinfo->desegment_len = required_length - available;
                col_add_str(pinfo->cinfo, COL_INFO, info_column);
                return reported_length;
            }
            add_cell_info(info_column, &info_column_idx, 7);
            ti = proto_tree_add_item(tree, proto_cell, tvb, 0, -1, ENC_NA);
            cell_tree = proto_item_add_subtree(ti, ett_cell);
            proto_tree_add_item(cell_tree, hf_cell_circid, tvb, offset,
                    2, ENC_NA);
            proto_tree_add_item(cell_tree, hf_cell_command, tvb, offset + 2,
                    1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cell_tree, hf_cell_length, tvb, offset + 3,
                    2, ENC_BIG_ENDIAN);
            proto_tree_add_item(cell_tree, hf_cell_payload, tvb, offset + 5,
                    payload_length, ENC_NA);
            offset += required_length;
        } else {
            /* we just assume this is a cell packet of version >=4 (cellid is 4
             * octets and CELL_LEN is 514) */
            cell_command = tvb_get_guint8(tvb, offset + 4);
            if (cell_command == 7) /* version command */ {
                /* this really shouldn't happen as it has a different offset;
                 * dissector cannot continue */
                col_add_str(pinfo->cinfo, COL_INFO, info_column);
                return offset;
            } else if (cell_command >= 128) {
                /* variable length command */
                /* the tvb_get_ntohs below is fine because it operates within
                 * CELL_MIN_LENGTH */
                payload_length = tvb_get_ntohs(tvb, offset + 5);
                required_length = payload_length + 7;
            } else {
                /* fixed length command */
                payload_length = CELL_FIXED_LENGTH - 5;
                required_length = CELL_FIXED_LENGTH;
            }
            if (available < required_length) {
                /* we are running out of data, ask for more */
                pinfo->desegment_offset = offset;
                /* TODO: used correctly? */
                pinfo->desegment_len = required_length - available;
                col_add_str(pinfo->cinfo, COL_INFO, info_column);
                return reported_length;
            }
            /* we have enough data */
            add_cell_info(info_column, &info_column_idx, cell_command);
            ti = proto_tree_add_item(tree, proto_cell, tvb, 0, -1, ENC_NA);
            cell_tree = proto_item_add_subtree(ti, ett_cell);
            proto_tree_add_item(cell_tree, hf_cell_circid, tvb, offset,
                    4, ENC_NA);
            proto_tree_add_item(cell_tree, hf_cell_command, tvb, offset + 4,
                    1, ENC_BIG_ENDIAN);
            offset += 5;
            if (cell_command >= 128) {
                proto_tree_add_item(cell_tree, hf_cell_length, tvb, offset,
                        2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            proto_tree_add_item(cell_tree, hf_cell_payload, tvb, offset,
                    payload_length, ENC_NA);
            offset += payload_length;
        }
    }

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    col_add_str(pinfo->cinfo, COL_INFO, info_column);
    /* Return the amount of data this dissector was able to dissect */
    return reported_length;
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_cell(void)
{
    module_t *cell_module;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_cell_circid,
            { "CircID", "cell.circid",
               FT_BYTES, BASE_NONE, NULL, 0,
              "Circuit Identifier", HFILL }
        },
        { &hf_cell_command,
            { "Command", "cell.command",
               FT_UINT8, BASE_DEC, VALS(cell_commands), 0,
              "Cell command", HFILL }
        },
        { &hf_cell_length,
            { "Length", "cell.length",
               FT_UINT16, BASE_DEC, NULL, 0,
              "Cell length", HFILL }
        },
        { &hf_cell_payload,
            { "Payload", "cell.payload",
               FT_BYTES, BASE_NONE, NULL, 0,
              "Cell payload (padded with 0 bytes)", HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_cell
    };

    /* Register the protocol name and description */
    proto_cell = proto_register_protocol("Tor cell protocol", "cell", "cell");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_cell, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_cell in the following.
     */
    cell_module = prefs_register_protocol(proto_cell,
            proto_reg_handoff_cell);

    /* dissect on ports setting */
    range_convert_str(&global_cell_ssl_range, SSL_CELL_DEFAULT_PORT_RANGE,
            65535);
    prefs_register_range_preference(cell_module, "ssl.port", "SSL/TLS Ports",
            "SSL/TLS Ports range", &global_cell_ssl_range, 65535);
}

static void
range_delete_cell_ssl_callback(guint32 port) {
	// ORIGINAL: ssl_dissector_delete(port, "cell", TRUE);
    ssl_dissector_delete(port, cell_handle);
}

static void
range_add_cell_ssl_callback(guint32 port) {
	// ORIGINAL: ssl_dissector_add(port, "cell", TRUE);
    ssl_dissector_add(port, cell_handle);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_cell(void)
{
    static gboolean initialized = FALSE;
    static range_t *cell_ssl_range = NULL;

    if (!initialized) {
        /* Use new_create_dissector_handle() to indicate that
         * dissect_cell() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to PROTONAME).
         */
        //OLD: cell_handle = new_register_dissector("cell", dissect_cell, proto_cell);
        cell_handle = register_dissector("cell", dissect_cell, proto_cell);
        dissector_add_uint("tcp.port", 0, cell_handle);
        initialized = TRUE;

    } else {
        /* remove any old registrations, we will register them fresh below */
        range_foreach(cell_ssl_range, range_delete_cell_ssl_callback);
        g_free(cell_ssl_range);
    }

    cell_ssl_range = range_copy(global_cell_ssl_range);
    range_foreach(cell_ssl_range, range_add_cell_ssl_callback);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
