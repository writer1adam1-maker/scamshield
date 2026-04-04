declare module 'ahocorasick' {
  class AhoCorasick {
    constructor(keywords: string[]);
    search(text: string): Array<[number, string[]]>;
  }
  export = AhoCorasick;
}
