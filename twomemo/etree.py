import base64
from typing import Dict, Optional, Set, Tuple, cast
import xml.etree.ElementTree as ET

from omemo import EncryptedKeyMaterial, KeyExchange, Message
import x3dh
try:
    import xmlschema
except ImportError as e:
    raise ImportError(
        "Optional dependency xmlschema not found. Please install xmlschema, or install this package using"
        " `pip install python-twomemo[xml]`, to use the ElementTree-based XML serialization/parser helpers."
    ) from e

from .twomemo import NAMESPACE, BundleImpl, ContentImpl, EncryptedKeyMaterialImpl, KeyExchangeImpl


__all__ = [  # pylint: disable=unused-variable
    "serialize_device_list",
    "parse_device_list",
    "serialize_bundle",
    "parse_bundle",
    "serialize_message",
    "parse_message"
]


NS = f"{{{NAMESPACE}}}"


DEVICE_LIST_SCHEMA = xmlschema.XMLSchema("""<?xml version='1.0' encoding='UTF-8'?>
<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'
           targetNamespace='urn:xmpp:omemo:2'
           xmlns='urn:xmpp:omemo:2'>

    <xs:element name='devices'>
        <xs:complexType>
            <xs:sequence maxOccurs='unbounded'>
                <xs:element ref='device'/>
            </xs:sequence>
        </xs:complexType>
    </xs:element>

    <xs:element name='device'>
        <xs:complexType>
            <xs:attribute name='id' type='xs:unsignedInt' use='required'/>
            <xs:attribute name='label' type='xs:string'/>
        </xs:complexType>
    </xs:element>
</xs:schema>
""")


BUNDLE_SCHEMA = xmlschema.XMLSchema("""<?xml version='1.0' encoding='UTF-8'?>
<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'
           targetNamespace='urn:xmpp:omemo:2'
           xmlns='urn:xmpp:omemo:2'>

    <xs:element name='bundle'>
        <xs:complexType>
            <xs:all>
                <xs:element ref='spk'/>
                <xs:element ref='spks'/>
                <xs:element ref='ik'/>
                <xs:element ref='prekeys'/>
            </xs:all>
        </xs:complexType>
    </xs:element>

    <xs:element name='spk'>
        <xs:complexType>
            <xs:simpleContent>
                <xs:extension base='xs:base64Binary'>
                    <xs:attribute name='id' type='xs:unsignedInt' use='required'/>
                </xs:extension>
            </xs:simpleContent>
        </xs:complexType>
    </xs:element>

    <xs:element name='spks' type='xs:base64Binary'/>
    <xs:element name='ik' type='xs:base64Binary'/>

    <xs:element name='prekeys'>
        <xs:complexType>
            <xs:sequence maxOccurs='unbounded'>
                <xs:element ref='pk'/>
            </xs:sequence>
        </xs:complexType>
    </xs:element>

    <xs:element name='pk'>
        <xs:complexType>
            <xs:simpleContent>
                <xs:extension base='xs:base64Binary'>
                    <xs:attribute name='id' type='xs:unsignedInt' use='required'/>
                </xs:extension>
            </xs:simpleContent>
        </xs:complexType>
    </xs:element>
</xs:schema>
""")


MESSAGE_SCHEMA = xmlschema.XMLSchema("""<?xml version='1.0' encoding='UTF-8'?>
<xs:schema xmlns:xs='http://www.w3.org/2001/XMLSchema'
           targetNamespace='urn:xmpp:omemo:2'
           xmlns='urn:xmpp:omemo:2'>

    <xs:element name='encrypted'>
        <xs:complexType>
            <xs:all>
                <xs:element ref='header'/>
                <xs:element ref='payload' minOccurs='0' maxOccurs='1'/>
            </xs:all>
        </xs:complexType>
    </xs:element>

    <xs:element name='payload' type='xs:base64Binary'/>

    <xs:element name='header'>
        <xs:complexType>
            <xs:sequence maxOccurs='unbounded'>
                <xs:element ref='keys'/>
            </xs:sequence>
            <xs:attribute name='sid' type='xs:unsignedInt'/>
        </xs:complexType>
    </xs:element>

    <xs:element name='keys'>
        <xs:complexType>
            <xs:sequence maxOccurs='unbounded'>
                <xs:element ref='key'/>
            </xs:sequence>
            <xs:attribute name='jid' type='xs:string' use='required'/>
        </xs:complexType>
    </xs:element>

    <xs:element name='key'>
        <xs:complexType>
            <xs:simpleContent>
                <xs:extension base='xs:base64Binary'>
                    <xs:attribute name='rid' type='xs:unsignedInt' use='required'/>
                    <xs:attribute name='kex' type='xs:boolean' default='false'/>
                </xs:extension>
            </xs:simpleContent>
        </xs:complexType>
    </xs:element>
</xs:schema>
""")


def serialize_device_list(device_list: Dict[int, Optional[str]]) -> ET.Element:
    """
    Args:
        device_list: The device list to serialize. The first entry of each tuple is the device id, and the
            second entry is the optional label.

    Returns:
        The serialized device list as an XML element.
    """

    devices_elt = ET.Element(f"{NS}devices")

    for device_id, label in device_list.items():
        device_elt = ET.SubElement(devices_elt, f"{NS}device")
        device_elt.set("id", str(device_id))
        if label is not None:
            device_elt.set("label", label)

    return devices_elt


def parse_device_list(element: ET.Element) -> Dict[int, Optional[str]]:
    """
    Args:
        element: The XML element to parse the device list from.

    Returns:
        The extracted device list. The first entry of each tuple is the device id, and the second entry is the
        optional label.

    Raises:
        XMLSchemaValidationError: in case the element does not conform to the XML schema given in the
            specification.
    """

    DEVICE_LIST_SCHEMA.validate(element)

    return {
        int(cast(str, device_elt.get("id"))): device_elt.get("label", None)
        for device_elt
        in element.iter(f"{NS}device")
    }


def serialize_bundle(bundle: BundleImpl) -> ET.Element:
    """
    Args:
        bundle: The bundle to serialize.

    Returns:
        The serialized bundle as an XML element.
    """

    bundle_elt = ET.Element(f"{NS}bundle")

    ET.SubElement(
        bundle_elt,
        f"{NS}spk",
        attrib={ "id": str(bundle.signed_pre_key_id) }
    ).text = base64.b64encode(bundle.bundle.signed_pre_key).decode("ASCII")

    ET.SubElement(
        bundle_elt,
        f"{NS}spks"
    ).text = base64.b64encode(bundle.bundle.signed_pre_key_sig).decode("ASCII")

    ET.SubElement(
        bundle_elt,
        f"{NS}ik"
    ).text = base64.b64encode(bundle.bundle.identity_key).decode("ASCII")

    prekeys_elt = ET.SubElement(bundle_elt, f"{NS}prekeys")
    for pre_key in bundle.bundle.pre_keys:
        ET.SubElement(
            prekeys_elt,
            f"{NS}pk",
            attrib={ "id": str(bundle.pre_key_ids[pre_key]) }
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
        XMLSchemaValidationError: in case the element does not conform to the XML schema given in the
            specification.
    """

    BUNDLE_SCHEMA.validate(element)

    spk_elt = cast(ET.Element, element.find(f"{NS}spk"))
    pk_elts = list(element.iter(f"{NS}pk"))

    return BundleImpl(
        bare_jid,
        device_id,
        x3dh.Bundle(
            base64.b64decode(cast(str, cast(ET.Element, element.find(f"{NS}ik")).text)),
            base64.b64decode(cast(str, spk_elt.text)),
            base64.b64decode(cast(str, cast(ET.Element, element.find(f"{NS}spks")).text)),
            frozenset(base64.b64decode(cast(str, pk_elt.text)) for pk_elt in pk_elts)
        ),
        int(cast(str, spk_elt.get("id"))),
        { base64.b64decode(cast(str, pk_elt.text)): int(cast(str, pk_elt.get("id"))) for pk_elt in pk_elts }
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

    for bare_jid in frozenset(encrypted_key_material.bare_jid for encrypted_key_material, _ in message.keys):
        keys_elt = ET.SubElement(header_elt, f"{NS}keys", attrib={ "jid": bare_jid })

        keys = frozenset(key for key in message.keys if key[0].bare_jid == bare_jid)
        for encrypted_key_material, key_exchange in keys:
            assert isinstance(encrypted_key_material, EncryptedKeyMaterialImpl)

            key_elt = ET.SubElement(
                keys_elt,
                f"{NS}key",
                attrib={ "rid": str(encrypted_key_material.device_id) }
            )

            authenticated_message = encrypted_key_material.serialize()

            if key_exchange is None:
                key_elt.text = base64.b64encode(authenticated_message).decode("ASCII")
            else:
                assert isinstance(key_exchange, KeyExchangeImpl)

                key_elt.set("kex", "true")
                key_elt.text = base64.b64encode(key_exchange.serialize(authenticated_message)).decode("ASCII")

    if not message.content.empty:
        ET.SubElement(
            encrypted_elt,
            f"{NS}payload"
        ).text = base64.b64encode(message.content.ciphertext).decode("ASCII")

    return encrypted_elt


def parse_message(element: ET.Element, bare_jid: str) -> Message:
    """
    Args:
        element: The XML element to parse the message from.
        bare_jid: The bare JID of the sender.

    Returns:
        The extracted message.

    Raises:
        ValueError: in case there is malformed data not caught be the XML schema validation.
        XMLSchemaValidationError: in case the element does not conform to the XML schema given in the
            specification.
    """

    MESSAGE_SCHEMA.validate(element)

    payload_elt = element.find(f"{NS}payload")

    keys: Set[Tuple[EncryptedKeyMaterial, Optional[KeyExchange]]] = set()

    for keys_elt in element.iter(f"{NS}keys"):
        recipient_bare_jid = cast(str, keys_elt.get("jid"))

        for key_elt in keys_elt.iter(f"{NS}key"):
            recipient_device_id = int(cast(str, key_elt.get("rid")))
            content = base64.b64decode(cast(str, key_elt.text))

            key_exchange: Optional[KeyExchangeImpl] = None
            authenticated_message: bytes
            if bool(key_elt.get("kex", False)):
                key_exchange, authenticated_message = KeyExchangeImpl.parse(content)
            else:
                authenticated_message = content

            encrypted_key_material = EncryptedKeyMaterialImpl.parse(
                authenticated_message,
                recipient_bare_jid,
                recipient_device_id
            )

            keys.add((encrypted_key_material, key_exchange))

    return Message(
        NAMESPACE,
        bare_jid,
        int(cast(str, cast(ET.Element, element.find(f"{NS}header")).get("sid"))),
        (
            ContentImpl.make_empty()
            if payload_elt is None
            else ContentImpl(base64.b64decode(cast(str, payload_elt.text)))
        ),
        frozenset(keys)
    )
