{
	let content = read('%s/ec_key_%d.json');
	let key_pair = JSON.parse(content);

	key1 = key_pair['key1']
	key2 = key_pair['key2']

	s1 = ec.keyFromPrivate(key1, 'hex');
	s2 = ec.keyFromPrivate(key2, 'hex');

	s1_pub = s1.getPublic();
	s2_pub = s2.getPublic();
}
