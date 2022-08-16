import base64
from typing import Dict, Optional, Set, Tuple, cast
import xml.etree.ElementTree as ET

from omemo import EncryptedKeyMaterial, KeyExchange, Message
import x3dh
import xeddsa
try:
    import xmlschema
except ImportError as e:
    raise ImportError(
        "Optional dependency xmlschema not found. Please install xmlschema, or install this package using"
        " `pip install oldmemo[xml]`, to use the ElementTree-based XML serialization/parser helpers."
    ) from e

from .oldmemo import NAMESPACE, BundleImpl, ContentImpl, EncryptedKeyMaterialImpl, KeyExchangeImpl


__all__ = [
    "serialize_device_list",
    "parse_device_list",
    "serialize_bundle",
    "parse_bundle",
    "serialize_message",
    "parse_message"
]


NS = f"{{{NAMESPACE}}}"


DEVICE_LIST_SCHEMA = xmlschema.XMLSchema("""<?xml version="1.0" encoding="utf8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
    targetNamespace="eu.siacs.conversations.axolotl"
    xmlns="eu.siacs.conversations.axolotl">

    <xs:element name="device">
        <xs:complexType>
            <xs:attribute name="id" type="xs:unsignedInt" use="required"/>
        </xs:complexType>
    </xs:element>

    <xs:element name="list">
        <xs:complexType>
            <xs:sequence minOccurs="0" maxOccurs="unbounded">
                <xs:element ref="device"/>
            </xs:sequence>
        </xs:complexType>
    </xs:element>
</xs:schema>
""")


BUNDLE_SCHEMA = xmlschema.XMLSchema("""<?xml version="1.0" encoding="utf8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
    targetNamespace="eu.siacs.conversations.axolotl"
    xmlns="eu.siacs.conversations.axolotl">

    <xs:element name="signedPreKeyPublic">
        <xs:complexType>
            <xs:simpleContent>
                <xs:extension base='xs:base64Binary'>
                    <xs:attribute name="signedPreKeyId" type="xs:unsignedInt"/>
                </xs:extension>
            </xs:simpleContent>
        </xs:complexType>
    </xs:element>

    <xs:element name='signedPreKeySignature' type='xs:base64Binary'/>
    <xs:element name='identityKey' type='xs:base64Binary'/>

    <xs:element name="preKeyPublic">
        <xs:complexType>
            <xs:simpleContent>
                <xs:extension base='xs:base64Binary'>
                    <xs:attribute name="preKeyId" type="xs:unsignedInt" use="required"/>
                </xs:extension>
            </xs:simpleContent>
        </xs:complexType>
    </xs:element>

    <xs:element name="prekeys">
        <xs:complexType>
            <xs:sequence>
                <xs:element ref="preKeyPublic" maxOccurs="unbounded"/>
            </xs:sequence>
        </xs:complexType>
    </xs:element>

    <xs:element name="bundle">
        <xs:complexType>
            <xs:sequence>
                <xs:element ref="signedPreKeyPublic"/>
                <xs:element ref="signedPreKeySignature"/>
                <xs:element ref="identityKey"/>
                <xs:element ref="prekeys"/>
            </xs:sequence>
        </xs:complexType>
    </xs:element>
</xs:schema>
""")


MESSAGE_SCHEMA = xmlschema.XMLSchema("""<?xml version="1.0" encoding="utf8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
    targetNamespace="eu.siacs.conversations.axolotl"
    xmlns="eu.siacs.conversations.axolotl">

    <xs:element name="payload" type="xs:base64Binary"/>
    <xs:element name="iv" type="xs:base64Binary"/>

    <xs:element name="key">
        <xs:complexType>
            <xs:simpleContent>
                <xs:extension base='xs:base64Binary'>
                    <xs:attribute name="rid" type="xs:unsignedInt" use="required"/>
                    <xs:attribute name="prekey" type="xs:boolean"/>
                </xs:extension>
            </xs:simpleContent>
        </xs:complexType>
    </xs:element>

    <xs:element name="header">
        <xs:complexType>
            <xs:sequence>
                <xs:element ref="key" maxOccurs="unbounded"/>
                <xs:element ref="iv"/>
            </xs:sequence>
            <xs:attribute name="sid" type="xs:unsignedInt"/>
        </xs:complexType>
    </xs:element>

    <xs:element name="encrypted">
        <xs:complexType>
            <xs:all>
                <xs:element ref="header"/>
                <xs:element ref="payload" minOccurs="0"/>
            </xs:all>
        </xs:complexType>
    </xs:element>
</xs:schema>
""")


def serialize_device_list(device_list: Dict[int, Optional[str]]) -> ET.Element:
    """
    Args:
        device_list: The device list to serialize. The first entry of each tuple is the device id, and the
            second entry is the optional label. Note that labels are not supported by this version of the
            specification and will not be included in the XML.

    Returns:
        The serialized device list as an XML element.
    """

    list_elt = ET.Element(f"{NS}list")

    for device_id, _ in device_list.items():
        device_elt = ET.SubElement(list_elt, f"{NS}device")
        device_elt.set("id", str(device_id))

    return list_elt


def parse_device_list(element: ET.Element) -> Dict[int, Optional[str]]:
    """
    Args:
        element: The XML element to parse the device list from.

    Returns:
        The extracted device list. The first entry of each tuple is the device id, and the second entry is the
        optional label. Note that labels are not supported by this version of the specification, so all labels
        will be set to ``None``.

    Raises:
        xmlschema.XMLSchemaValidationError: in case the element does not conform to the XML schema given in
            the specification.
    """

    DEVICE_LIST_SCHEMA.validate(element)

    return { int(cast(str, device_elt.get("id"))): None for device_elt in element.iter(f"{NS}device") }


def serialize_bundle(bundle: BundleImpl) -> ET.Element:
    """
    Args:
        bundle: The bundle to serialize.

    Returns:
        The serialized bundle as an XML element.
    """

    bundle_elt = ET.Element(f"{NS}bundle")

    identity_key_sign = (bundle.bundle.identity_key[31] >> 7) & 1
    identity_key_serialized = b"\x05" + xeddsa.ed25519_pub_to_curve25519_pub(bundle.bundle.identity_key)
    signed_pre_key_signature_mut = bytearray(bundle.bundle.signed_pre_key_sig)
    signed_pre_key_signature_mut[63] |= identity_key_sign << 7
    signed_pre_key_signature = bytes(signed_pre_key_signature_mut)

    ET.SubElement(
        bundle_elt,
        f"{NS}signedPreKeyPublic",
        attrib={ "signedPreKeyId": str(bundle.signed_pre_key_id) }
    ).text = base64.b64encode(bundle.bundle.signed_pre_key).decode("ASCII")

    ET.SubElement(
        bundle_elt,
        f"{NS}signedPreKeySignature"
    ).text = base64.b64encode(signed_pre_key_signature).decode("ASCII")

    ET.SubElement(
        bundle_elt,
        f"{NS}identityKey"
    ).text = base64.b64encode(identity_key_serialized).decode("ASCII")

    prekeys_elt = ET.SubElement(bundle_elt, f"{NS}prekeys")
    for pre_key in bundle.bundle.pre_keys:
        ET.SubElement(
            prekeys_elt,
            f"{NS}preKeyPublic",
            attrib={ "preKeyId": str(bundle.pre_key_ids[pre_key]) }
        ).text = base64.b64encode(pre_key).decode("ASCII")

    return bundle_elt


def parse_bundle(element: ET.Element, bare_jid: str, device_id: int) -> BundleImpl:
    """
    Args:
        element: The XML element to parse the bundle from.
        bare_jid: The bare JID this bundle belongs to.
        device_id: The device id of the specific device this bundle belongs to.

    Returns:
        The extracted bundle.

    Raises:
        xmlschema.XMLSchemaValidationError: in case the element does not conform to the XML schema given in
            the specification.
    """

    BUNDLE_SCHEMA.validate(element)

    spkp_elt = cast(ET.Element, element.find(f"{NS}signedPreKeyPublic"))
    pkp_elts = list(element.iter(f"{NS}preKeyPublic"))

    signed_pre_key_signature = base64.b64decode(cast(str, cast(ET.Element, element.find(
        f"{NS}signedPreKeySignature"
    )).text))

    identity_key_sign = (signed_pre_key_signature[63] >> 7) & 1

    signed_pre_key_signature_mut = bytearray(signed_pre_key_signature)
    signed_pre_key_signature_mut[63] &= 0x7f
    signed_pre_key_signature = bytes(signed_pre_key_signature_mut)

    identity_key_serialized = base64.b64decode(cast(str, cast(ET.Element, element.find(
        f"{NS}identityKey"
    )).text))

    assert identity_key_serialized[0] == 0x05

    identity_key = xeddsa.curve25519_pub_to_ed25519_pub(identity_key_serialized[1:], bool(identity_key_sign))

    return BundleImpl(
        bare_jid,
        device_id,
        x3dh.Bundle(
            identity_key,
            base64.b64decode(cast(str, spkp_elt.text)),
            signed_pre_key_signature,
            frozenset(base64.b64decode(cast(str, pkp_elt.text)) for pkp_elt in pkp_elts)
        ),
        int(cast(str, spkp_elt.get("signedPreKeyId"))),
        {
            base64.b64decode(cast(str, pkp_elt.text)): int(cast(str, pkp_elt.get("preKeyId")))
            for pkp_elt
            in pkp_elts
        }
    )


def serialize_message(message: Message) -> ET.Element:
    """
    Args:
        message: The message to serialize.

    Returns:
        The serialized message as an XML element.
    """

    assert isinstance(message.content, ContentImpl)

    encrypted_elt = ET.Element(f"{NS}encrypted")

    header_elt = ET.SubElement(encrypted_elt, f"{NS}header", attrib={ "sid": str(message.device_id) })

    for encrypted_key_material, key_exchange in message.keys:
        assert isinstance(encrypted_key_material, EncryptedKeyMaterialImpl)

        key_elt = ET.SubElement(
            header_elt,
            f"{NS}key",
            attrib={ "rid": str(encrypted_key_material.device_id) }
        )

        authenticated_message = b"\x33" + encrypted_key_material.serialize()

        if key_exchange is None:
            key_elt.text = base64.b64encode(authenticated_message).decode("ASCII")
        else:
            assert isinstance(key_exchange, KeyExchangeImpl)

            key_elt.set("prekey", "true")
            key_elt.text = base64.b64encode(
                b"\x33" + key_exchange.serialize(authenticated_message)
            ).decode("ASCII")

    if not message.content.empty:
        ET.SubElement(
            header_elt,
            f"{NS}iv"
        ).text = base64.b64encode(message.content.initialization_vector).decode("ASCII")

        ET.SubElement(
            encrypted_elt,
            f"{NS}payload"
        ).text = base64.b64encode(message.content.ciphertext).decode("ASCII")

    return encrypted_elt


def parse_message(element: ET.Element, sender_bare_jid: str, recipient_bare_jid: str) -> Message:
    """
    Args:
        element: The XML element to parse the message from.
        sender_bare_jid: The bare JID of the sender.
        recipient_bare_jid: The bare JID of the recipient, i.e. us.

    Returns:
        The extracted message.

    Raises:
        ValueError: in case there is malformed data not caught be the XML schema validation.
        xmlschema.XMLSchemaValidationError: in case the element does not conform to the XML schema given in
            the specification.

    Warning:
        This version of the OMEMO specification matches key material to recipient purely by device id. The
        library, however, matches by bare JID and device id. Since the XML doesn't include the bare JID, the
        structures expected by the library can't be filled correctly. Instead, to match the behaviour of the
        specification, the bare JID of all key material included in the message is assigned to
        ``recipient_bare_jid``, i.e. our own bare JID, which achieves the desired effect of matching only on
        the device id.
    """

    MESSAGE_SCHEMA.validate(element)

    payload_elt = element.find(f"{NS}payload")
    header_elt = cast(ET.Element, element.find(f"{NS}header"))
    iv_elt = header_elt.find(f"{NS}iv")

    keys: Set[Tuple[EncryptedKeyMaterial, Optional[KeyExchange]]] = set()

    for key_elt in header_elt.iter(f"{NS}key"):
        recipient_device_id = int(cast(str, key_elt.get("rid")))
        content = base64.b64decode(cast(str, key_elt.text))

        key_exchange: Optional[KeyExchangeImpl] = None
        authenticated_message: bytes
        if key_elt.get("prekey", "false") in [ "true", "1" ]:
            version, content = content[0], content[1:]

            if version != 0x33:
                raise Exception("Unexpected version byte.")

            key_exchange, authenticated_message = KeyExchangeImpl.parse(content)
        else:
            authenticated_message = content

        version, authenticated_message = authenticated_message[0], authenticated_message[1:]

        if version != 0x33:
            raise Exception("Unexpected version byte.")

        encrypted_key_material = EncryptedKeyMaterialImpl.parse(
            authenticated_message,
            recipient_bare_jid,
            recipient_device_id
        )

        keys.add((encrypted_key_material, key_exchange))

    return Message(
        NAMESPACE,
        sender_bare_jid,
        int(cast(str, header_elt.get("sid"))),
        (
            ContentImpl.make_empty()
            if payload_elt is None or iv_elt is None
            else ContentImpl(
                base64.b64decode(cast(str, payload_elt.text)),
                base64.b64decode(cast(str, iv_elt.text))
            )
        ),
        frozenset(keys)
    )
